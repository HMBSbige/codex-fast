use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::patch::{PATCH_SET, PatchPlan, PatchSetReport, Planner};
use crate::platform::IdentityFile;
use crate::trace;

const ASAR_PICKLE_PREFIX_SIZE: usize = 8;
const ASAR_MAX_HEADER_SIZE: u32 = 64 * 1024 * 1024;

/// SHA-256 of a file at inspection time. Content changes always change the digest,
/// so size and mtime would add no coverage — and mtime alone would fail on a mere touch.
#[derive(Clone, Debug)]
struct FileSnapshot {
    sha256: String,
}

#[derive(Clone, Debug)]
pub struct PlannedResource {
    pub archive_path: String,
    pub request_paths: BTreeSet<String>,
    pub labels: BTreeSet<&'static str>,
    pub required_for_ready: bool,
    pub patched_content: String,
}

#[derive(Clone, Debug)]
pub struct CompatibilityPlan {
    verification_snapshots: Vec<VerificationSnapshot>,
    pub patch_set: PatchSetReport,
    pub resources: Vec<PlannedResource>,
}

#[derive(Clone, Debug)]
struct VerificationSnapshot {
    label: &'static str,
    path: PathBuf,
    snapshot: FileSnapshot,
}

#[derive(Clone, Debug)]
struct AsarFile {
    path: String,
    size: u64,
    offset: u64,
    unpacked: bool,
    integrity_hash: Option<String>,
}

struct ReadOnlyAsarArchive {
    file: File,
    files: Vec<AsarFile>,
    data_offset: u64,
}

pub fn plan_patches(app_asar: &Path, identity_files: &[IdentityFile]) -> Result<CompatibilityPlan> {
    let mut verification_snapshots = vec![VerificationSnapshot {
        label: "app.asar",
        path: app_asar.to_owned(),
        snapshot: snapshot_file(app_asar)?,
    }];
    verification_snapshots.extend(
        identity_files
            .iter()
            .map(|file| {
                Ok(VerificationSnapshot {
                    label: file.label,
                    path: file.path.clone(),
                    snapshot: snapshot_file(&file.path)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    );
    let mut archive = ReadOnlyAsarArchive::open(app_asar)
        .with_context(|| format!("open {}", app_asar.display()))?;

    let mut planner = Planner::new(&PATCH_SET);

    let ReadOnlyAsarArchive {
        file,
        files,
        data_offset,
    } = &mut archive;
    for entry in files.iter().filter(|entry| is_scannable_entry(entry)) {
        let bytes = read_packed_file(file, *data_offset, entry)
            .with_context(|| format!("read ASAR entry {}", entry.path))?;
        // Skipping is fail-closed only per Core feature: one that loses *every* site this
        // way drops to zero and blocks launch, but one split across two resources still
        // reports Complete with the skipped resource left unpatched. A UiEntry feature
        // that loses its sites only degrades, and the app still starts.
        //
        // Lossy decoding would be worse. Invalid bytes in a comment or string literal
        // become U+FFFD and still parse, so the entry would be patched and injected.
        let Ok(body) = String::from_utf8(bytes) else {
            trace(format_args!("ASAR_ENTRY_NOT_UTF8 path={}", entry.path));
            continue;
        };
        planner
            .scan(&entry.path, body)
            .with_context(|| format!("inspect ASAR entry {}", entry.path))?;
    }

    let PatchPlan {
        report: patch_set,
        resources: patched_resources,
    } = planner.finish().context("plan static patch sets")?;
    let target_archive_paths = patched_resources
        .iter()
        .map(|resource| resource.key.clone())
        .collect::<Vec<_>>();
    ensure_patch_targets_packed(&archive.files, &target_archive_paths)?;
    let mut request_paths_by_archive =
        resource_request_paths(&archive.files, &target_archive_paths)?;

    let resources = patched_resources
        .into_iter()
        .map(|resource| {
            let archive_path = resource.key;
            // `resource_request_paths` only ever inserts paths that passed
            // `is_safe_request_path`, so there is nothing left to re-check here.
            let request_paths = request_paths_by_archive
                .remove(&archive_path)
                .ok_or_else(|| anyhow!("missing request paths for {archive_path}"))?;
            Ok(PlannedResource {
                archive_path,
                request_paths,
                labels: resource.labels,
                required_for_ready: resource.required_for_ready,
                patched_content: resource.patched_content,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(CompatibilityPlan {
        verification_snapshots,
        patch_set,
        resources,
    })
}

fn ensure_patch_targets_packed(
    archive_files: &[AsarFile],
    target_archive_paths: &[String],
) -> Result<()> {
    for path in target_archive_paths {
        let entry = archive_files
            .iter()
            .find(|entry| entry.path == *path)
            .ok_or_else(|| anyhow!("missing ASAR patch target {path}"))?;
        if entry.unpacked {
            bail!("unpacked ASAR patch target is not snapshot-safe: {path}");
        }
    }
    Ok(())
}

pub fn verify_plan_snapshots(plan: &CompatibilityPlan) -> Result<()> {
    for file in &plan.verification_snapshots {
        assert_snapshot(file.label, &file.path, &file.snapshot)?;
    }
    Ok(())
}

fn resource_request_paths(
    archive_files: &[AsarFile],
    target_archive_paths: &[String],
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut suffix_counts = target_archive_paths
        .iter()
        .flat_map(|path| path_suffixes(path))
        .map(|suffix| (suffix.to_owned(), 0usize))
        .collect::<BTreeMap<_, _>>();
    for path in archive_files
        .iter()
        .map(|entry| entry.path.as_str())
        .filter(|path| is_javascript_path(path))
    {
        for suffix in path_suffixes(path) {
            if let Some(count) = suffix_counts.get_mut(suffix) {
                *count += 1;
            }
        }
    }

    let renderer_roots = archive_files
        .iter()
        .filter(|entry| is_html_path(&entry.path))
        .map(|entry| posix_dirname(&entry.path))
        .filter(|root| {
            target_archive_paths
                .iter()
                .all(|path| relative_to_root(root, path).is_some())
        })
        .collect::<BTreeSet<_>>();

    let request_paths = target_archive_paths
        .iter()
        .map(|archive_path| {
            let unique_suffix = path_suffixes(archive_path)
                .filter(|path| suffix_counts.get(*path) == Some(&1))
                .filter(|path| is_safe_request_path(path))
                .min_by_key(|path| path.len())
                .map(str::to_owned);
            let mut request_paths = BTreeSet::new();
            for root in &renderer_roots {
                if let Some(path) = relative_to_root(root, archive_path)
                    && is_safe_request_path(path)
                {
                    request_paths.insert(path.to_owned());
                }
            }
            if let Some(unique_suffix) = unique_suffix {
                request_paths.insert(unique_suffix);
            }
            if request_paths.is_empty() {
                bail!("could not derive a request path for {archive_path}");
            }
            Ok((archive_path.clone(), request_paths))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let mut unique_paths = BTreeSet::new();
    for path in request_paths.values().flatten() {
        if !unique_paths.insert(path) {
            bail!("ambiguous request path {path}");
        }
    }
    Ok(request_paths)
}

pub(crate) fn path_suffixes(path: &str) -> impl Iterator<Item = &str> {
    std::iter::once(path).chain(path.match_indices('/').map(|(index, _)| &path[index + 1..]))
}

fn is_javascript_path(path: &str) -> bool {
    let name = basename(path);
    name.len() > ".js".len() && ends_with_extension_ci(name, ".js")
}

/// Unpacked entries live outside the archive the launch-time snapshot covers, so
/// `ensure_patch_targets_packed` refuses to patch them. Excluding them here keeps a
/// sidecar file that happens to match a pattern from becoming a target that blocks launch.
fn is_scannable_entry(entry: &AsarFile) -> bool {
    !entry.unpacked && is_javascript_path(&entry.path)
}

fn is_html_path(path: &str) -> bool {
    ends_with_extension_ci(basename(path), ".html")
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

fn ends_with_extension_ci(name: &str, extension: &str) -> bool {
    name.len() >= extension.len()
        && name
            .get(name.len() - extension.len()..)
            .is_some_and(|actual| actual.eq_ignore_ascii_case(extension))
}

fn posix_dirname(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(directory, _)| directory)
        .unwrap_or_default()
}

fn relative_to_root<'path>(root: &str, path: &'path str) -> Option<&'path str> {
    if root.is_empty() {
        return Some(path);
    }
    path.strip_prefix(root)
        .and_then(|relative| relative.strip_prefix('/'))
}

pub(crate) fn is_safe_request_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'-'
                        | b'_'
                        | b'.'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'@'
                )
        })
}

impl ReadOnlyAsarArchive {
    fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size_pickle = read_exact_at(&mut file, ASAR_PICKLE_PREFIX_SIZE, 0)?;
        if u32_le(&size_pickle, 0) != 4 {
            bail!("unsupported ASAR size pickle format");
        }
        let header_size = u32_le(&size_pickle, 4);
        if header_size < ASAR_PICKLE_PREFIX_SIZE as u32
            || header_size > ASAR_MAX_HEADER_SIZE
            || ASAR_PICKLE_PREFIX_SIZE as u64 + header_size as u64 > metadata.len()
        {
            bail!("invalid ASAR header size {header_size}");
        }

        let header_pickle = read_exact_at(
            &mut file,
            header_size as usize,
            ASAR_PICKLE_PREFIX_SIZE as u64,
        )?;
        let json = header_json(&header_pickle)?;
        let header: Value = serde_json::from_slice(json).context("invalid ASAR header JSON")?;
        let data_offset = ASAR_PICKLE_PREFIX_SIZE as u64 + header_size as u64;
        let mut files = Vec::new();
        flatten_files(&header, "", metadata.len(), data_offset, &mut files)?;

        Ok(Self {
            file,
            files,
            data_offset,
        })
    }
}

fn read_packed_file(file: &mut File, data_offset: u64, entry: &AsarFile) -> Result<Vec<u8>> {
    debug_assert!(!entry.unpacked);
    // Re-checks what `flatten_files` proved, because tests in this module can construct
    // `AsarFile` directly without going through it.
    let offset = data_offset
        .checked_add(entry.offset)
        .ok_or_else(|| anyhow!("ASAR entry offset overflows: {}", entry.path))?;
    let length = usize::try_from(entry.size)
        .with_context(|| format!("ASAR entry is too large to read: {}", entry.path))?;
    let content = read_exact_at(file, length, offset)?;
    if content.len() as u64 != entry.size {
        bail!("unexpected size for ASAR entry {}", entry.path);
    }
    if let Some(expected) = &entry.integrity_hash {
        let actual = sha256_hex_bytes(&content);
        if !actual.eq_ignore_ascii_case(expected) {
            bail!("integrity check failed for ASAR entry {}", entry.path);
        }
    }
    Ok(content)
}

fn flatten_files(
    entry: &Value,
    parent: &str,
    archive_size: u64,
    data_offset: u64,
    files: &mut Vec<AsarFile>,
) -> Result<()> {
    let children = entry
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("ASAR header missing files object under {parent}"))?;

    for (name, child) in children {
        validate_entry_name(name, parent)?;
        let entry_path = if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        };
        if child.get("files").is_some() {
            flatten_files(child, &entry_path, archive_size, data_offset, files)?;
            continue;
        }
        if child.get("link").is_some() {
            continue;
        }
        let size = child
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("invalid ASAR size for {entry_path}"))?;
        let unpacked = child
            .get("unpacked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let offset = if unpacked {
            0
        } else {
            child
                .get("offset")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("missing ASAR offset for {entry_path}"))?
                .parse::<u64>()
                .with_context(|| format!("invalid ASAR offset for {entry_path}"))?
        };
        // A sum that wraps would clear this check and then ask `read_packed_file` to allocate
        // the wrapped-away length.
        if !unpacked
            && data_offset
                .checked_add(offset)
                .and_then(|start| start.checked_add(size))
                .is_none_or(|end| end > archive_size)
        {
            bail!("ASAR entry {entry_path} extends past the archive");
        }
        let integrity_hash = child
            .get("integrity")
            .and_then(|value| value.get("hash"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        files.push(AsarFile {
            path: entry_path,
            size,
            offset,
            unpacked,
            integrity_hash,
        });
    }
    Ok(())
}

fn validate_entry_name(name: &str, parent: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        bail!("invalid ASAR entry name {name:?} under {parent}");
    }
    Ok(())
}

fn read_exact_at(file: &mut File, length: usize, offset: u64) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Header JSON inside the header pickle.
///
/// The comparisons widen to `u64` because these lengths come from the file: in `u32` they
/// wrap, and a wrapped length clears all three checks and then slices out of bounds.
fn header_json(header_pickle: &[u8]) -> Result<&[u8]> {
    let payload_size = u32_le(header_pickle, 0);
    let json_size = u32_le(header_pickle, 4);
    let header_size = header_pickle.len() as u64;
    if u64::from(payload_size) + 4 > header_size
        || json_size > payload_size.saturating_sub(4)
        || ASAR_PICKLE_PREFIX_SIZE as u64 + u64::from(json_size) > header_size
    {
        bail!("invalid ASAR header pickle lengths");
    }
    let start = ASAR_PICKLE_PREFIX_SIZE;
    Ok(&header_pickle[start..start + json_size as usize])
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn snapshot_file(path: &Path) -> Result<FileSnapshot> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(FileSnapshot {
        sha256: lower_hex(&hasher.finalize()),
    })
}

fn assert_snapshot(label: &str, path: &Path, expected: &FileSnapshot) -> Result<()> {
    if snapshot_file(path)?.sha256 != expected.sha256 {
        bail!("{label} changed after compatibility inspection");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::{
        AsarFile, ensure_patch_targets_packed, flatten_files, header_json, is_javascript_path,
        resource_request_paths,
    };

    fn file(path: &str) -> AsarFile {
        AsarFile {
            path: path.to_owned(),
            size: 0,
            offset: 0,
            unpacked: false,
            integrity_hash: None,
        }
    }

    #[test]
    fn rejects_header_pickle_lengths_that_wrap_a_u32() {
        // Both `payload_size + 4` and `8 + json_size` wrap to 0, which clears all three
        // checks and leaves a json_end of 2^32 pointing past an 8-byte pickle.
        let mut pickle = (u32::MAX - 3).to_le_bytes().to_vec();
        pickle.extend_from_slice(&(u32::MAX - 7).to_le_bytes());

        let error = header_json(&pickle).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("invalid ASAR header pickle lengths")
        );
    }

    #[test]
    fn accepts_a_well_formed_header_pickle() {
        let mut pickle = 8u32.to_le_bytes().to_vec();
        pickle.extend_from_slice(&4u32.to_le_bytes());
        pickle.extend_from_slice(b"null");

        assert_eq!(header_json(&pickle).unwrap(), b"null");
    }

    #[test]
    fn rejects_entry_bounds_that_wrap_a_u64() {
        let data_offset = 24u64;
        for child in [
            json!({ "size": u64::MAX - data_offset + 1, "offset": "0" }),
            json!({ "size": 1u64, "offset": u64::MAX.to_string() }),
        ] {
            let header = json!({ "files": { "a.js": child } });
            let mut files = Vec::new();

            let error = flatten_files(&header, "", 4096, data_offset, &mut files).unwrap_err();

            assert!(error.to_string().contains("extends past the archive"));
        }
    }

    #[test]
    fn recognizes_only_supported_renderer_javascript_paths() {
        assert!(is_javascript_path("assets/settings-abc.js"));
        assert!(is_javascript_path("assets/settings-abc.JS"));
        assert!(is_javascript_path(".vite/build/settings-abc.js"));
        assert!(is_javascript_path("static/js/nested/settings-abc.js"));

        assert!(!is_javascript_path("assets/.js"));
        assert!(!is_javascript_path("assets/settings.css"));
    }

    #[test]
    fn rejects_unpacked_patch_targets_without_a_snapshot() {
        let mut unpacked = file("assets/settings.js");
        unpacked.unpacked = true;

        let error = ensure_patch_targets_packed(&[unpacked], &["assets/settings.js".to_owned()])
            .unwrap_err();

        assert!(error.to_string().contains("not snapshot-safe"));
    }

    #[test]
    fn derives_the_shortest_globally_unique_resource_suffix() {
        let files = [
            "future/static/js/settings.js",
            "future/chunks/composer.js",
            "other/settings.js",
        ]
        .into_iter()
        .map(file)
        .collect::<Vec<_>>();
        let targets = vec![
            "future/static/js/settings.js".to_owned(),
            "future/chunks/composer.js".to_owned(),
        ];

        let paths = resource_request_paths(&files, &targets).unwrap();

        assert_eq!(
            paths[&targets[0]],
            BTreeSet::from(["js/settings.js".to_owned()])
        );
        assert_eq!(
            paths[&targets[1]],
            BTreeSet::from(["composer.js".to_owned()])
        );
    }

    #[test]
    fn derives_renderer_relative_paths_despite_backend_suffix_collisions() {
        let target = "webview/assets/settings.JS".to_owned();

        for html_path in ["webview/shell.HTML", "webview/.HTML"] {
            let files = [
                html_path,
                "webview/assets/settings.JS",
                "backend/webview/assets/settings.JS",
            ]
            .into_iter()
            .map(file)
            .collect::<Vec<_>>();

            let paths = resource_request_paths(&files, std::slice::from_ref(&target)).unwrap();

            assert_eq!(
                paths[&target],
                BTreeSet::from(["assets/settings.JS".to_owned()])
            );
        }
    }

    #[test]
    fn rejects_request_paths_shared_through_nested_renderer_roots() {
        let files = [
            "index.html",
            "webview/index.html",
            "webview/assets/app.js",
            "webview/webview/assets/app.js",
        ]
        .into_iter()
        .map(file)
        .collect::<Vec<_>>();
        let targets = vec![
            "webview/assets/app.js".to_owned(),
            "webview/webview/assets/app.js".to_owned(),
        ];

        let error = resource_request_paths(&files, &targets).unwrap_err();

        assert!(error.to_string().contains("ambiguous request path"));
    }
}

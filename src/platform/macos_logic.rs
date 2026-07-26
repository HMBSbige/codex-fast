use std::path::{Component, Path, PathBuf};

/// Chromium reads CDP commands from fd 3 and writes responses to fd 4.
/// Copies are parked at or above [`TEMPORARY_FD_MIN`] so remapping never clobbers a source.
#[cfg(target_os = "macos")]
pub(super) const COMMAND_FD: i32 = 3;
#[cfg(target_os = "macos")]
pub(super) const RESPONSE_FD: i32 = 4;
#[cfg(target_os = "macos")]
pub(super) const TEMPORARY_FD_MIN: i32 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BundlePaths {
    pub info_plist: PathBuf,
    pub app_asar: PathBuf,
    pub code_resources: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PlistInfo {
    pub identifier: String,
    pub executable: String,
    pub version: String,
    pub build: String,
}

pub(super) fn bundle_paths(bundle: &Path) -> BundlePaths {
    let contents = bundle.join("Contents");
    BundlePaths {
        info_plist: contents.join("Info.plist"),
        app_asar: contents.join("Resources").join("app.asar"),
        code_resources: contents.join("_CodeSignature").join("CodeResources"),
    }
}

pub(super) fn bundle_executable(bundle: &Path, executable: &str) -> Option<PathBuf> {
    let mut components = Path::new(executable).components();
    let name = match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => name,
        _ => return None,
    };
    Some(bundle.join("Contents").join("MacOS").join(name))
}

pub(super) fn parse_plistbuddy_output(output: &str) -> Result<PlistInfo, &'static str> {
    let values = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if values.len() != 4 {
        return Err("PlistBuddy did not return four values");
    }
    Ok(PlistInfo {
        identifier: values[0].to_owned(),
        executable: values[1].to_owned(),
        version: values[2].to_owned(),
        build: values[3].to_owned(),
    })
}

pub(super) fn ps_has_executable(
    output: &str,
    executable: &Path,
    excluded_pid: Option<u32>,
) -> bool {
    let executable = executable.to_string_lossy();
    output.lines().any(|line| {
        parse_ps_line(line).is_some_and(|(pid, command)| {
            Some(pid) != excluded_pid && command_starts_with_executable(command, &executable)
        })
    })
}

fn parse_ps_line(line: &str) -> Option<(u32, &str)> {
    let line = line.trim_start();
    let pid_end = line.find(char::is_whitespace)?;
    let pid = line[..pid_end].parse().ok()?;
    let command = line[pid_end..].trim_start();
    (!command.is_empty()).then_some((pid, command))
}

fn command_starts_with_executable(command: &str, executable: &str) -> bool {
    command
        .strip_prefix(executable)
        .or_else(|| {
            ['"', '\''].into_iter().find_map(|quote| {
                command
                    .strip_prefix(quote)?
                    .strip_prefix(executable)?
                    .strip_prefix(quote)
            })
        })
        .is_some_and(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{bundle_executable, bundle_paths, parse_plistbuddy_output, ps_has_executable};

    #[test]
    fn derives_standard_bundle_paths() {
        let paths = bundle_paths(Path::new("/Applications/Codex.app"));
        assert_eq!(
            paths.info_plist,
            PathBuf::from("/Applications/Codex.app/Contents/Info.plist")
        );
        assert_eq!(
            paths.app_asar,
            PathBuf::from("/Applications/Codex.app/Contents/Resources/app.asar")
        );
        assert_eq!(
            paths.code_resources,
            PathBuf::from("/Applications/Codex.app/Contents/_CodeSignature/CodeResources")
        );
    }

    #[test]
    fn accepts_only_a_bundle_executable_name() {
        let bundle = Path::new("/Applications/Codex.app");
        assert_eq!(
            bundle_executable(bundle, "Codex"),
            Some(PathBuf::from(
                "/Applications/Codex.app/Contents/MacOS/Codex"
            ))
        );
        assert_eq!(bundle_executable(bundle, "../Codex"), None);
        assert_eq!(bundle_executable(bundle, "helpers/Codex"), None);
        assert_eq!(bundle_executable(bundle, "/tmp/Codex"), None);
    }

    #[test]
    fn parses_plistbuddy_values_in_query_order() {
        let info = parse_plistbuddy_output("com.openai.codex\nCodex\n1.2.3\n456\n").unwrap();
        assert_eq!(info.identifier, "com.openai.codex");
        assert_eq!(info.executable, "Codex");
        assert_eq!(info.version, "1.2.3");
        assert_eq!(info.build, "456");
        assert!(parse_plistbuddy_output("com.openai.codex\nCodex\n").is_err());
    }

    #[test]
    fn matches_only_the_exact_ps_executable_and_honors_exclusion() {
        let ps = concat!(
            "  101 /Applications/Codex.app/Contents/MacOS/Codex --flag\n",
            "  102 /Applications/Codex.app/Contents/MacOS/CodexHelper --flag\n",
            "  103 \"/Applications/Codex App.app/Contents/MacOS/Codex App\" --flag\n",
        );
        assert!(ps_has_executable(
            ps,
            Path::new("/Applications/Codex.app/Contents/MacOS/Codex"),
            None
        ));
        assert!(!ps_has_executable(
            ps,
            Path::new("/Applications/Codex.app/Contents/MacOS/Codex"),
            Some(101)
        ));
        assert!(ps_has_executable(
            ps,
            Path::new("/Applications/Codex App.app/Contents/MacOS/Codex App"),
            None
        ));
    }
}

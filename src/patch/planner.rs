//! Cross-resource planning for statically compiled patch sets.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};

use crate::js_tokens::Tokens;
use crate::patch::{Edit, FeatureRole, PatchSet, Site};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatchStatus {
    Complete,
    Degraded,
    Unsafe,
}

#[derive(Clone, Debug)]
pub(crate) struct FeatureReport {
    pub id: &'static str,
    pub label: &'static str,
    pub role: FeatureRole,
    pub guarded_sites: usize,
    pub patched_sites: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct PatchSetReport {
    pub id: &'static str,
    pub label: &'static str,
    pub status: PatchStatus,
    pub features: Vec<FeatureReport>,
    pub messages: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct PatchedResource {
    pub key: String,
    pub patched_content: String,
    pub labels: BTreeSet<&'static str>,
    pub required_for_ready: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PatchPlan {
    pub report: PatchSetReport,
    pub resources: Vec<PatchedResource>,
}

struct ScannedResource {
    content: String,
    sites: Vec<Vec<Site>>,
}

/// Accumulates JavaScript resources and tokenizes each one exactly once per pass.
pub(crate) struct Planner {
    patch_set: &'static PatchSet,
    resources: BTreeMap<String, ScannedResource>,
}

impl Planner {
    pub fn new(patch_set: &'static PatchSet) -> Self {
        Self {
            patch_set,
            resources: BTreeMap::new(),
        }
    }

    /// Adds one JavaScript resource. ASAR traversal can call this incrementally.
    pub fn scan(&mut self, key: &str, content: String) -> Result<()> {
        if self.resources.contains_key(key) {
            bail!("duplicate patch resource: {key}");
        }
        let Some(sites) = detect_resource(self.patch_set, &content) else {
            return Ok(());
        };
        if sites.iter().all(Vec::is_empty) {
            return Ok(());
        }
        self.resources
            .insert(key.to_owned(), ScannedResource { content, sites });
        Ok(())
    }

    pub fn finish(self) -> Result<PatchPlan> {
        let mut report = initial_report(self.patch_set, &self.resources);
        if report.status == PatchStatus::Unsafe {
            return Ok(blocked_plan(report));
        }

        let edits = collect_edits(&self.resources);
        if record_failures(&mut report, edit_conflicts(&edits)) {
            return Ok(blocked_plan(report));
        }

        let patched_contents = patch_resources(&self.resources, &edits)?;
        let after = patched_contents
            .iter()
            .map(|content| {
                detect_resource(self.patch_set, content)
                    .unwrap_or_else(|| vec![Vec::new(); self.patch_set.features.len()])
            })
            .collect::<Vec<_>>();
        let failures =
            verification_failures(self.patch_set, &self.resources, &patched_contents, &after);
        if record_failures(&mut report, failures) {
            return Ok(blocked_plan(report));
        }

        let resources = build_resources(self.patch_set, self.resources, patched_contents);
        Ok(PatchPlan { report, resources })
    }
}

impl PatchSetReport {
    pub(crate) fn format_messages(&self, heading: &str) -> String {
        let mut lines = vec![heading.to_owned(), format!("{} ({}):", self.label, self.id)];
        lines.extend(self.messages.iter().map(|message| format!("- {message}")));
        lines.join("\n")
    }
}

fn detect_resource(patch_set: &PatchSet, content: &str) -> Option<Vec<Vec<Site>>> {
    let active = patch_set
        .features
        .iter()
        .map(|feature| feature.is_active(content))
        .collect::<Vec<_>>();
    if !active.iter().any(|active| *active) {
        return None;
    }
    let tokens = Tokens::new(content);
    Some(
        patch_set
            .features
            .iter()
            .zip(active)
            .map(|(feature, active)| {
                if active {
                    feature.detect_sites(&tokens)
                } else {
                    Vec::new()
                }
            })
            .collect(),
    )
}

fn initial_report(
    patch_set: &PatchSet,
    resources: &BTreeMap<String, ScannedResource>,
) -> PatchSetReport {
    let features = patch_set
        .features
        .iter()
        .enumerate()
        .map(|(feature_index, feature)| {
            let (guarded_sites, patched_sites) = resources
                .values()
                .flat_map(|resource| &resource.sites[feature_index])
                .fold((0, 0), |(guarded, patched), site| {
                    if site.edits.is_empty() {
                        (guarded, patched + 1)
                    } else {
                        (guarded + 1, patched)
                    }
                });
            FeatureReport {
                id: feature.id,
                label: feature.label,
                role: feature.role,
                guarded_sites,
                patched_sites,
            }
        })
        .collect::<Vec<_>>();
    let mut report = PatchSetReport {
        id: patch_set.id,
        label: patch_set.label,
        status: PatchStatus::Complete,
        features,
        messages: Vec::new(),
    };

    let missing = report
        .features
        .iter()
        .filter(|feature| feature.guarded_sites + feature.patched_sites == 0)
        .map(|feature| (feature.role, feature.label, feature.id))
        .collect::<Vec<_>>();
    for (role, label, id) in missing {
        let message = format!("{label} ({id}) was not found");
        match role {
            FeatureRole::Core => mark_unsafe(&mut report, message),
            FeatureRole::UiEntry => mark_degraded(&mut report, message),
        }
    }

    for (key, resource) in resources {
        for (feature_index, sites) in resource.sites.iter().enumerate() {
            for site in sites {
                if let Some(reason) = invalid_site(&resource.content, site) {
                    mark_unsafe(
                        &mut report,
                        format!(
                            "{} in {key} is unsafe: {reason}",
                            patch_set.features[feature_index].label
                        ),
                    );
                }
            }
        }
    }
    report
}

fn invalid_site(content: &str, site: &Site) -> Option<&'static str> {
    if !valid_range(content, &site.range) {
        return Some("invalid site range");
    }
    if site.edits.iter().any(|edit| {
        !valid_range(content, &edit.range)
            || edit.range.start < site.range.start
            || edit.range.end > site.range.end
    }) {
        return Some("invalid edit range");
    }
    None
}

fn valid_range(content: &str, range: &std::ops::Range<usize>) -> bool {
    range.start < range.end
        && range.end <= content.len()
        && content.is_char_boundary(range.start)
        && content.is_char_boundary(range.end)
}

fn mark_degraded(report: &mut PatchSetReport, message: String) {
    if report.status == PatchStatus::Complete {
        report.status = PatchStatus::Degraded;
    }
    report.messages.push(message);
}

fn mark_unsafe(report: &mut PatchSetReport, message: String) {
    report.status = PatchStatus::Unsafe;
    report.messages.push(message);
}

fn record_failures(report: &mut PatchSetReport, failures: Vec<String>) -> bool {
    if failures.is_empty() {
        return false;
    }
    report.status = PatchStatus::Unsafe;
    report.messages.extend(failures);
    true
}

fn blocked_plan(report: PatchSetReport) -> PatchPlan {
    PatchPlan {
        report,
        resources: Vec::new(),
    }
}

struct GlobalEdit {
    resource: usize,
    edit: Edit,
}

fn collect_edits(resources: &BTreeMap<String, ScannedResource>) -> Vec<GlobalEdit> {
    let mut edits = Vec::new();
    for (resource_index, resource) in resources.values().enumerate() {
        for site in resource.sites.iter().flatten() {
            for edit in &site.edits {
                edits.push(GlobalEdit {
                    resource: resource_index,
                    edit: edit.clone(),
                });
            }
        }
    }
    edits.sort_by(|left, right| {
        (
            left.resource,
            left.edit.range.start,
            left.edit.range.end,
            &left.edit.replacement,
        )
            .cmp(&(
                right.resource,
                right.edit.range.start,
                right.edit.range.end,
                &right.edit.replacement,
            ))
    });
    edits.dedup_by(|left, right| left.resource == right.resource && left.edit == right.edit);
    edits
}

fn edit_conflicts(edits: &[GlobalEdit]) -> Vec<String> {
    let mut failures = Vec::new();
    for (left_index, left) in edits.iter().enumerate() {
        for right in &edits[left_index + 1..] {
            if right.resource != left.resource {
                break;
            }
            if right.edit.range.start >= left.edit.range.end {
                break;
            }
            failures.push(format!(
                "overlapping edits at {}..{} and {}..{}",
                left.edit.range.start,
                left.edit.range.end,
                right.edit.range.start,
                right.edit.range.end
            ));
        }
    }
    failures
}

fn patch_resources(
    resources: &BTreeMap<String, ScannedResource>,
    edits: &[GlobalEdit],
) -> Result<Vec<String>> {
    let mut patched = Vec::with_capacity(resources.len());
    let mut edit_index = 0;
    for (resource_index, resource) in resources.values().enumerate() {
        let start = edit_index;
        while edit_index < edits.len() && edits[edit_index].resource == resource_index {
            edit_index += 1;
        }
        patched.push(apply_sorted_edits(
            &resource.content,
            edits[start..edit_index].iter().map(|edit| &edit.edit),
        )?);
    }
    debug_assert_eq!(edit_index, edits.len());
    Ok(patched)
}

fn verification_failures(
    patch_set: &PatchSet,
    before: &BTreeMap<String, ScannedResource>,
    patched_contents: &[String],
    after: &[Vec<Vec<Site>>],
) -> Vec<String> {
    debug_assert_eq!(before.len(), patched_contents.len());
    debug_assert_eq!(before.len(), after.len());
    let mut failures = Vec::new();
    for (feature_index, feature) in patch_set.features.iter().enumerate() {
        for (((key, before_resource), patched_content), after_resource) in
            before.iter().zip(patched_contents).zip(after)
        {
            let before_sites = &before_resource.sites[feature_index];
            let after_sites = &after_resource[feature_index];
            let message = if after_sites.len() != before_sites.len() {
                Some(format!(
                    "{} site count changed in {key} from {} to {} after patching",
                    feature.label,
                    before_sites.len(),
                    after_sites.len()
                ))
            } else if let Some(reason) = after_sites
                .iter()
                .find_map(|site| invalid_site(patched_content, site))
            {
                Some(format!(
                    "{} in {key} is unsafe after patching: {reason}",
                    feature.label
                ))
            } else if after_sites.iter().any(|site| !site.edits.is_empty()) {
                Some(format!(
                    "{} in {key} did not re-detect as fully patched",
                    feature.label
                ))
            } else {
                None
            };
            if let Some(message) = message {
                failures.push(message);
            }
        }
    }
    failures
}

fn build_resources(
    patch_set: &PatchSet,
    resources: BTreeMap<String, ScannedResource>,
    patched_contents: Vec<String>,
) -> Vec<PatchedResource> {
    resources
        .into_iter()
        .zip(patched_contents)
        .map(|((key, resource), patched_content)| {
            let mut labels = BTreeSet::new();
            let mut required_for_ready = false;
            for (feature_index, sites) in resource.sites.iter().enumerate() {
                if sites.is_empty() {
                    continue;
                }
                let feature = &patch_set.features[feature_index];
                labels.insert(feature.label);
                required_for_ready |= feature.role == FeatureRole::Core;
            }
            PatchedResource {
                key,
                patched_content,
                labels,
                required_for_ready,
            }
        })
        .collect()
}

/// Applies exact edits once. Identical edits are deduplicated; all other overlaps fail closed.
#[cfg(test)]
pub(crate) fn apply_edits(source: &str, edits: &[Edit]) -> Result<String> {
    let mut edits = edits.iter().collect::<Vec<_>>();
    edits.sort_by(|left, right| {
        (left.range.start, left.range.end, &left.replacement).cmp(&(
            right.range.start,
            right.range.end,
            &right.replacement,
        ))
    });
    edits.dedup();

    apply_sorted_edits(source, edits)
}

fn apply_sorted_edits<'a>(
    source: &str,
    edits: impl IntoIterator<Item = &'a Edit>,
) -> Result<String> {
    let mut previous_end = 0;
    let mut output = String::with_capacity(source.len());
    for edit in edits {
        if !valid_range(source, &edit.range) || edit.range.start < previous_end {
            bail!("invalid or overlapping patch edits");
        }
        output.push_str(&source[previous_end..edit.range.start]);
        output.push_str(&edit.replacement);
        previous_end = edit.range.end;
    }
    output.push_str(&source[previous_end..]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::Feature;

    fn replace_old_with_new(tokens: &Tokens<'_>) -> Vec<Site> {
        replace_ident(tokens, "old", "new")
    }

    fn replace_old_with_other(tokens: &Tokens<'_>) -> Vec<Site> {
        replace_ident(tokens, "old", "other")
    }

    fn expand_old(tokens: &Tokens<'_>) -> Vec<Site> {
        replace_ident(tokens, "old", "new new")
    }

    fn detect_nothing(_: &Tokens<'_>) -> Vec<Site> {
        Vec::new()
    }

    fn never_settles(tokens: &Tokens<'_>) -> Vec<Site> {
        (0..tokens.len())
            .filter(|&index| matches!(tokens.text(index), "old" | "new"))
            .map(|index| {
                let range = tokens.span(index);
                Site {
                    range: range.clone(),
                    edits: vec![Edit {
                        range,
                        replacement: "new".to_owned(),
                    }],
                }
            })
            .collect()
    }

    fn disappear_old(tokens: &Tokens<'_>) -> Vec<Site> {
        (0..tokens.len())
            .filter_map(|index| match tokens.text(index) {
                "old" => {
                    let range = tokens.span(index);
                    Some(Site {
                        range: range.clone(),
                        edits: vec![Edit {
                            range,
                            replacement: "gone".to_owned(),
                        }],
                    })
                }
                "new" => Some(Site {
                    range: tokens.span(index),
                    edits: Vec::new(),
                }),
                _ => None,
            })
            .collect()
    }

    fn seed_new_site(tokens: &Tokens<'_>) -> Vec<Site> {
        replace_ident(tokens, "seed", "new")
    }

    fn invalid_after_patch(tokens: &Tokens<'_>) -> Vec<Site> {
        let mut sites = replace_ident(tokens, "old", "new");
        for site in &mut sites {
            if site.edits.is_empty() {
                site.range.end = usize::MAX;
            }
        }
        sites
    }

    fn replace_ident(tokens: &Tokens<'_>, guarded: &str, patched: &str) -> Vec<Site> {
        (0..tokens.len())
            .filter_map(|index| {
                let text = tokens.text(index);
                if text != guarded && text != patched {
                    return None;
                }
                let range = tokens.span(index);
                let edits = if text == guarded {
                    vec![Edit {
                        range: range.clone(),
                        replacement: patched.to_owned(),
                    }]
                } else {
                    Vec::new()
                };
                Some(Site { range, edits })
            })
            .collect()
    }

    const CORE_FEATURES: &[Feature] = &[Feature {
        id: "core",
        label: "Core",
        role: FeatureRole::Core,
        anchors: &[],
        detect: replace_old_with_new,
    }];
    const EXPANDING_FEATURES: &[Feature] = &[Feature {
        id: "expanding",
        label: "Expanding",
        role: FeatureRole::Core,
        anchors: &[],
        detect: expand_old,
    }];
    const UNSTABLE_FEATURES: &[Feature] = &[Feature {
        id: "unstable",
        label: "Unstable",
        role: FeatureRole::Core,
        anchors: &[],
        detect: never_settles,
    }];
    const RELOCATING_FEATURES: &[Feature] = &[
        Feature {
            id: "relocating",
            label: "Relocating",
            role: FeatureRole::Core,
            anchors: &[],
            detect: disappear_old,
        },
        Feature {
            id: "seed",
            label: "Seed",
            role: FeatureRole::Core,
            anchors: &[],
            detect: seed_new_site,
        },
    ];
    const INVALID_POST_FEATURES: &[Feature] = &[Feature {
        id: "invalid-post",
        label: "Invalid post",
        role: FeatureRole::Core,
        anchors: &[],
        detect: invalid_after_patch,
    }];
    const DUPLICATE_FEATURES: &[Feature] = &[
        Feature {
            id: "first",
            label: "First",
            role: FeatureRole::Core,
            anchors: &[],
            detect: replace_old_with_new,
        },
        Feature {
            id: "second",
            label: "Second",
            role: FeatureRole::Core,
            anchors: &[],
            detect: replace_old_with_new,
        },
    ];
    const CONFLICTING_FEATURES: &[Feature] = &[
        Feature {
            id: "first",
            label: "First",
            role: FeatureRole::Core,
            anchors: &[],
            detect: replace_old_with_new,
        },
        Feature {
            id: "second",
            label: "Second",
            role: FeatureRole::Core,
            anchors: &[],
            detect: replace_old_with_other,
        },
    ];

    static BLOCKING_SET: PatchSet = PatchSet {
        id: "required",
        label: "Required",
        features: CORE_FEATURES,
    };
    static EXPANDING_SET: PatchSet = PatchSet {
        id: "expanding",
        label: "Expanding",
        features: EXPANDING_FEATURES,
    };
    static DUPLICATE_SET: PatchSet = PatchSet {
        id: "duplicate",
        label: "Duplicate",
        features: DUPLICATE_FEATURES,
    };
    static CONFLICTING_SET: PatchSet = PatchSet {
        id: "conflicting",
        label: "Conflicting",
        features: CONFLICTING_FEATURES,
    };
    static UNSTABLE_SET: PatchSet = PatchSet {
        id: "unstable",
        label: "Unstable",
        features: UNSTABLE_FEATURES,
    };
    static RELOCATING_SET: PatchSet = PatchSet {
        id: "relocating",
        label: "Relocating",
        features: RELOCATING_FEATURES,
    };
    static INVALID_POST_SET: PatchSet = PatchSet {
        id: "invalid-post",
        label: "Invalid post",
        features: INVALID_POST_FEATURES,
    };

    #[test]
    fn feature_accepts_multiple_sites() {
        let mut planner = Planner::new(&BLOCKING_SET);
        planner.scan("a.js", "old+old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Complete);
        assert_eq!(plan.report.features[0].guarded_sites, 2);
        assert_eq!(plan.resources[0].patched_content, "new+new");
    }

    #[test]
    fn missing_ui_is_degraded_but_patchable() {
        const FEATURES: &[Feature] = &[
            Feature {
                id: "core",
                label: "Core",
                role: FeatureRole::Core,
                anchors: &[],
                detect: replace_old_with_new,
            },
            Feature {
                id: "ui",
                label: "UI",
                role: FeatureRole::UiEntry,
                anchors: &[],
                detect: detect_nothing,
            },
        ];
        static SET: PatchSet = PatchSet {
            id: "set",
            label: "Set",
            features: FEATURES,
        };
        let mut planner = Planner::new(&SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Degraded);
        assert_eq!(plan.resources[0].patched_content, "new");
    }

    #[test]
    fn missing_core_blocks_without_emitting_resources() {
        let planner = Planner::new(&BLOCKING_SET);
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
    }

    #[test]
    fn identical_edits_are_deduplicated_across_features() {
        let mut planner = Planner::new(&DUPLICATE_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Complete);
        assert_eq!(plan.resources[0].patched_content, "new");
        assert!(plan.resources[0].required_for_ready);
    }

    #[test]
    fn ui_only_resources_do_not_block_runtime_readiness() {
        const FEATURES: &[Feature] = &[Feature {
            id: "ui",
            label: "UI",
            role: FeatureRole::UiEntry,
            anchors: &[],
            detect: replace_old_with_new,
        }];
        static SET: PatchSet = PatchSet {
            id: "ui-only",
            label: "UI only",
            features: FEATURES,
        };
        let mut planner = Planner::new(&SET);
        planner.scan("ui.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Complete);
        assert!(!plan.resources[0].required_for_ready);
    }

    #[test]
    fn different_overlapping_required_edits_block_launch() {
        let mut planner = Planner::new(&CONFLICTING_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
        assert!(
            plan.report
                .messages
                .iter()
                .any(|message| message.contains("overlapping edits"))
        );
    }

    #[test]
    fn changed_site_count_fails_post_verification() {
        let mut planner = Planner::new(&EXPANDING_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
        assert!(
            plan.report
                .messages
                .iter()
                .any(|message| message.contains("site count changed"))
        );
    }

    #[test]
    fn a_second_guarded_pass_fails_idempotence() {
        let mut planner = Planner::new(&UNSTABLE_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
        assert!(
            plan.report
                .messages
                .iter()
                .any(|message| message.contains("fully patched"))
        );
    }

    #[test]
    fn sites_cannot_move_between_resources_during_verification() {
        let mut planner = Planner::new(&RELOCATING_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        planner.scan("b.js", "seed".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
        assert!(
            plan.report
                .messages
                .iter()
                .any(|message| message.contains("a.js") && message.contains("site count"))
        );
    }

    #[test]
    fn invalid_post_patch_site_is_unsafe() {
        let mut planner = Planner::new(&INVALID_POST_SET);
        planner.scan("a.js", "old".to_owned()).unwrap();
        let plan = planner.finish().unwrap();

        assert_eq!(plan.report.status, PatchStatus::Unsafe);
        assert!(plan.resources.is_empty());
        assert!(
            plan.report
                .messages
                .iter()
                .any(|message| message.contains("invalid site range"))
        );
    }
}

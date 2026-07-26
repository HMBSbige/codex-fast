//! Static JavaScript patch definitions and the shared patch planner.

use std::ops::Range;

use crate::js_tokens::Tokens;
use crate::token_match::{Atom, Hit, find, token_range};

mod fast;
mod planner;

pub(crate) use fast::PATCH_SET;
pub(crate) use planner::{PatchPlan, PatchSetReport, PatchStatus, Planner};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FeatureRole {
    Core,
    UiEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Edit {
    pub range: Range<usize>,
    pub replacement: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Site {
    /// Byte range that identifies this logical site, including already-patched sites.
    pub range: Range<usize>,
    /// Empty when this site is already patched.
    pub edits: Vec<Edit>,
}

pub(crate) struct Feature {
    pub id: &'static str,
    pub label: &'static str,
    pub role: FeatureRole,
    pub anchors: &'static [&'static str],
    pub detect: for<'source> fn(&Tokens<'source>) -> Vec<Site>,
}

impl Feature {
    fn detect_sites(&self, tokens: &Tokens<'_>) -> Vec<Site> {
        let mut sites = Vec::new();
        for site in (self.detect)(tokens) {
            if !sites.contains(&site) {
                sites.push(site);
            }
        }
        sites
    }

    fn is_active(&self, source: &str) -> bool {
        self.anchors.iter().all(|anchor| source.contains(anchor))
    }
}

type Rewrite = fn(&Tokens<'_>, &Hit) -> Option<Vec<Edit>>;
type Validate = fn(&Tokens<'_>, &Hit) -> bool;

fn pattern_sites(
    tokens: &Tokens<'_>,
    guarded: &[Atom],
    patched: &[Atom],
    rewrite: Rewrite,
    validate: Validate,
) -> Vec<Site> {
    let guarded = find(tokens, guarded)
        .filter(|hit| validate(tokens, hit))
        .filter_map(|hit| {
            Some(Site {
                range: token_range(tokens, hit.start, hit.end)?,
                edits: rewrite(tokens, &hit)?,
            })
        });
    let patched = find(tokens, patched)
        .filter(|hit| validate(tokens, hit))
        .filter_map(|hit| {
            Some(Site {
                range: token_range(tokens, hit.start, hit.end)?,
                edits: Vec::new(),
            })
        });
    guarded.chain(patched).collect()
}

pub(crate) struct PatchSet {
    pub id: &'static str,
    pub label: &'static str,
    pub features: &'static [Feature],
}

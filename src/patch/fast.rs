//! Fast unlock detection rules.

use std::ops::Range;

use crate::js_tokens::{Kind, Tokens};
use crate::patch::{Edit, Feature, FeatureRole, PatchSet, Site, pattern_sites};
use crate::token_match::Atom::*;
use crate::token_match::{Atom, Hit, any_in, find, take_bool_value, token_range};

const FAST_FEATURES: &[Feature] = &[
    Feature {
        id: "speed-setting-option-count",
        label: "Speed setting",
        role: FeatureRole::UiEntry,
        anchors: &["isServiceTierAllowed", "availableOptions"],
        detect: detect_speed_setting,
    },
    Feature {
        id: "speed-service-tier-allowance",
        label: "Speed service tier allowance",
        role: FeatureRole::Core,
        anchors: &[
            "featureRequirements",
            "authMethod",
            "fast_mode",
            "isServiceTierAllowed",
        ],
        detect: detect_allowance,
    },
    Feature {
        id: "speed-service-tier-request-allowance",
        label: "Speed service tier request allowance",
        role: FeatureRole::Core,
        anchors: &["authMethod", "priority"],
        detect: detect_request_allowance,
    },
    Feature {
        id: "speed-service-tier-conversation-fallback",
        label: "Speed service tier conversation fallback",
        role: FeatureRole::Core,
        anchors: &[
            "serviceTierForRequest",
            "selectedServiceTier",
            "isServiceTierAllowed",
        ],
        detect: detect_conversation_fallback,
    },
    Feature {
        id: "intelligence-speed-menu-options",
        label: "Composer Intelligence Speed menu",
        role: FeatureRole::UiEntry,
        anchors: &["composer.openModelPicker", "availableOptions"],
        detect: detect_intelligence_menu,
    },
    Feature {
        id: "service-tier-slash-command",
        label: "Fast slash command",
        role: FeatureRole::UiEntry,
        anchors: &["requiresEmptyComposer", "service-tier:${"],
        detect: detect_slash_command,
    },
];

pub(crate) const PATCH_SET: PatchSet = PatchSet {
    id: "fast-unlock",
    label: "Fast unlock",
    features: FAST_FEATURES,
};

fn always(_: &Tokens<'_>, _: &Hit) -> bool {
    true
}

const SPEED_GUARDED: &[Atom] = &[
    ExactRun("isServiceTierAllowed :"),
    Ident(0),
    ExactRun("} ="),
    AnyIdent,
    ExactRun("( ) , { serviceTierSettings :"),
    Ident(1),
    ExactRun(", setServiceTier :"),
    AnyIdent,
    ExactRun("} ="),
    AnyIdent,
    ExactRun("( ) ; if ("),
    Begin(0),
    ExactRun("!"),
    Ident(0),
    ExactRun("||"),
    End(0),
    Ident(1),
    Member("availableOptions"),
    Member("length"),
    ExactRun("<= 1 ) return null ;"),
];

const SPEED_PATCHED: &[Atom] = &[
    ExactRun("isServiceTierAllowed :"),
    Ident(0),
    ExactRun("} ="),
    AnyIdent,
    ExactRun("( ) , { serviceTierSettings :"),
    Ident(1),
    ExactRun(", setServiceTier :"),
    AnyIdent,
    ExactRun("} ="),
    AnyIdent,
    ExactRun("( ) ; if ("),
    Ident(1),
    Member("availableOptions"),
    Member("length"),
    ExactRun("<= 1 ) return null ;"),
];

fn detect_speed_setting(tokens: &Tokens<'_>) -> Vec<Site> {
    pattern_sites(
        tokens,
        SPEED_GUARDED,
        SPEED_PATCHED,
        remove_captured_span,
        always,
    )
}

fn remove_captured_span(tokens: &Tokens<'_>, hit: &Hit) -> Option<Vec<Edit>> {
    Some(vec![Edit {
        range: hit.span(tokens, 0)?,
        replacement: String::new(),
    }])
}

const AL_DATA: usize = 0;
const AL_PENDING: usize = 1;
const AL_LOADING: usize = 2;
const AL_SOURCE: usize = 3;
const AL_AUTH: usize = 4;
const AL_ALLOWED: usize = 5;

const ALLOWANCE_GUARDED: &[Atom] = &[
    OneOf(&["let", "const", "var"]),
    ExactRun("{ data :"),
    Ident(AL_DATA),
    ExactRun(", isPending :"),
    Ident(AL_PENDING),
    ExactRun("} ="),
    AnyIdent,
    ExactRun("("),
    AnyIdent,
    ExactRun(","),
    AnyIdent,
    ExactRun(") ,"),
    Ident(AL_LOADING),
    ExactRun("= ! !"),
    Ident(AL_SOURCE),
    Member("isLoading"),
    ExactRun("||"),
    Ident(AL_AUTH),
    ExactRun("&&"),
    Ident(AL_PENDING),
    ExactRun(","),
    Ident(AL_ALLOWED),
    ExactRun("="),
    Begin(0),
    Ident(AL_AUTH),
    ExactRun("&& !"),
    Ident(AL_LOADING),
    ExactRun("&&"),
    Ident(AL_DATA),
    NullNe,
    ExactRun("&&"),
    Ident(AL_DATA),
    Member("requirements"),
    Member("featureRequirements"),
    Member("fast_mode"),
    ExactRun("!=="),
    Bool(false),
    End(0),
    ExactRun(","),
];

const ALLOWANCE_PATCHED: &[Atom] = &[
    OneOf(&["let", "const", "var"]),
    ExactRun("{ data :"),
    Ident(AL_DATA),
    ExactRun(", isPending :"),
    Ident(AL_PENDING),
    ExactRun("} ="),
    AnyIdent,
    ExactRun("("),
    AnyIdent,
    ExactRun(","),
    AnyIdent,
    ExactRun(") ,"),
    Ident(AL_LOADING),
    ExactRun("= ! !"),
    Ident(AL_SOURCE),
    Member("isLoading"),
    ExactRun("||"),
    Ident(AL_AUTH),
    ExactRun("&&"),
    Ident(AL_PENDING),
    ExactRun(","),
    Ident(AL_ALLOWED),
    ExactRun("= !"),
    Ident(AL_LOADING),
    ExactRun("&& ("),
    Ident(AL_AUTH),
    ExactRun("?"),
    Ident(AL_DATA),
    NullNe,
    ExactRun("&&"),
    Ident(AL_DATA),
    Member("requirements"),
    Member("featureRequirements"),
    Member("fast_mode"),
    ExactRun("!=="),
    Bool(false),
    ExactRun(":"),
    Bool(true),
    ExactRun(") ,"),
];

const AUTH_CHATGPT: &[Atom] = &[
    Ident(AL_AUTH),
    ExactRun("="),
    Ident(AL_SOURCE),
    Member("authMethod"),
    OneOf(&["==", "==="]),
    Str("chatgpt"),
];

const NULLABLE_AUTH: &[Atom] = &[
    AnyIdent,
    ExactRun("="),
    Ident(AL_SOURCE),
    Member("authMethod"),
    ExactRun("?? null"),
];

fn detect_allowance(tokens: &Tokens<'_>) -> Vec<Site> {
    pattern_sites(
        tokens,
        ALLOWANCE_GUARDED,
        ALLOWANCE_PATCHED,
        |tokens, hit| {
            let loading = tokens.text(hit.ident(AL_LOADING));
            let auth = tokens.text(hit.ident(AL_AUTH));
            let data = tokens.text(hit.ident(AL_DATA));
            Some(vec![Edit {
                range: hit.span(tokens, 0)?,
                replacement: format!(
                    "!{loading}&&({auth}?{data}!=null&&{data}?.requirements?.featureRequirements?.fast_mode!==!1:!0)"
                ),
            }])
        },
        allowance_context,
    )
}

fn allowance_context(tokens: &Tokens<'_>, hit: &Hit) -> bool {
    let before = hit.start;
    let start = before.saturating_sub(180);
    any_in(tokens, start..before, AUTH_CHATGPT, Some(hit))
        && any_in(tokens, start..before, NULLABLE_AUTH, Some(hit))
        && has_object_mapping(
            tokens,
            hit.end,
            240,
            &[
                ("isServiceTierAllowed", hit.ident(AL_ALLOWED)),
                ("isLoading", hit.ident(AL_LOADING)),
            ],
        )
}

const REQ_CACHE: usize = 0;
const REQ_HOST: usize = 1;
const REQ_AUTH: usize = 2;
const REQ_RESPONSE: usize = 3;

const REQUEST_STATE: &[Atom] = &[
    ExactRun("async function"),
    AnyIdent,
    ExactRun("("),
    Ident(REQ_CACHE),
    ExactRun(","),
    Ident(REQ_HOST),
    ExactRun(") {"),
    OneOf(&["let", "const", "var"]),
    Ident(REQ_AUTH),
    ExactRun("= await"),
    AnyIdent,
    ExactRun("("),
    Ident(REQ_CACHE),
    ExactRun(","),
    Ident(REQ_HOST),
    ExactRun(") ; if ("),
    Ident(REQ_AUTH),
    ExactRun("!=="),
    Str("chatgpt"),
    ExactRun(") return"),
    NoLineBreak,
    Begin(0),
    CaptureBool(0),
    End(0),
    ExactRun(";"),
    OneOf(&["let", "const", "var"]),
    Ident(REQ_RESPONSE),
    ExactRun("= await"),
    AnyIdent,
    ExactRun("("),
    Ident(REQ_HOST),
    ExactRun(", { priority :"),
    Str("critical"),
    ExactRun("} ) ; return"),
    Ident(REQ_CACHE),
    Member("query"),
    Member("setData"),
    ExactRun("("),
    AnyIdent,
    ExactRun(", { authMethod :"),
    Ident(REQ_AUTH),
    ExactRun(", hostId :"),
    Ident(REQ_HOST),
    ExactRun("} ,"),
    Ident(REQ_RESPONSE),
    ExactRun(") ,"),
    Ident(REQ_RESPONSE),
    Member("requirements"),
    Member("featureRequirements"),
    Member("fast_mode"),
    ExactRun("!=="),
    Bool(false),
    ExactRun("}"),
];

fn detect_request_allowance(tokens: &Tokens<'_>) -> Vec<Site> {
    find(tokens, REQUEST_STATE)
        .filter_map(|hit| {
            let edits = if hit.boolean(0) {
                Vec::new()
            } else {
                vec![Edit {
                    range: hit.span(tokens, 0)?,
                    replacement: "!0".to_owned(),
                }]
            };
            Some(Site {
                range: token_range(tokens, hit.start, hit.end)?,
                edits,
            })
        })
        .collect()
}

const CV_EFFECTIVE: usize = 0;
const CV_CONVERSATION: usize = 1;
const CV_THREAD: usize = 2;
const CV_OVERRIDE: usize = 3;
const CV_BASE: usize = 4;
const CV_REQUEST: usize = 5;
const CV_ALLOWED: usize = 6;
const CV_FALLBACK: usize = 7;
const CV_MODEL: usize = 8;
const CV_SELECTED: usize = 9;

const CONVERSATION_GUARDED: &[Atom] = &[
    Ident(CV_BASE),
    ExactRun("="),
    AnyIdent,
    NullEq,
    ExactRun("&&"),
    AnyIdent,
    NullNe,
    ExactRun("?"),
    AnyIdent,
    Member("value"),
    ExactRun(":"),
    AnyIdent,
    ExactRun("?"),
    AnyIdent,
    ExactRun("("),
    AnyIdent,
    ExactRun(") :"),
    AnyIdent,
    Member("serviceTier"),
    ExactRun(","),
    Ident(CV_EFFECTIVE),
    ExactRun("="),
    Begin(0),
    Ident(CV_CONVERSATION),
    NullNe,
    ExactRun("&&"),
    Ident(CV_THREAD),
    Member("serviceTier"),
    ExactRun("!=="),
    Undefined,
    ExactRun("?"),
    Ident(CV_THREAD),
    Member("serviceTier"),
    ExactRun(":"),
    Ident(CV_CONVERSATION),
    NullNe,
    ExactRun("&&"),
    Ident(CV_OVERRIDE),
    ExactRun("!=="),
    Undefined,
    ExactRun("?"),
    Ident(CV_OVERRIDE),
    ExactRun(":"),
    Ident(CV_BASE),
    End(0),
    ExactRun(";"),
    Ident(CV_REQUEST),
    ExactRun("="),
    Begin(1),
    Ident(CV_CONVERSATION),
    NullNe,
    ExactRun("&& ("),
    Ident(CV_THREAD),
    Member("serviceTier"),
    ExactRun("!=="),
    Undefined,
    ExactRun("||"),
    Ident(CV_OVERRIDE),
    ExactRun("!=="),
    Undefined,
    ExactRun(") ?"),
    Ident(CV_ALLOWED),
    ExactRun("?"),
    Ident(CV_EFFECTIVE),
    ExactRun(": null :"),
    Ident(CV_FALLBACK),
    ExactRun("("),
    Ident(CV_MODEL),
    ExactRun(","),
    Ident(CV_EFFECTIVE),
    ExactRun(","),
    Ident(CV_ALLOWED),
    ExactRun(")"),
    End(1),
    ExactRun(","),
    Ident(CV_SELECTED),
    ExactRun("="),
    Ident(CV_REQUEST),
    NullEq,
    ExactRun("? null :"),
    AnyIdent,
    ExactRun("("),
    Ident(CV_MODEL),
    ExactRun(","),
    Ident(CV_REQUEST),
    ExactRun(")"),
];

const CONVERSATION_PATCHED: &[Atom] = &[
    Ident(CV_BASE),
    ExactRun("="),
    AnyIdent,
    NullEq,
    ExactRun("&&"),
    AnyIdent,
    NullNe,
    ExactRun("?"),
    AnyIdent,
    Member("value"),
    ExactRun(":"),
    AnyIdent,
    ExactRun("?"),
    AnyIdent,
    ExactRun("("),
    AnyIdent,
    ExactRun(") :"),
    AnyIdent,
    Member("serviceTier"),
    ExactRun(","),
    Ident(CV_EFFECTIVE),
    ExactRun("="),
    Ident(CV_BASE),
    ExactRun(";"),
    Ident(CV_REQUEST),
    ExactRun("="),
    Ident(CV_FALLBACK),
    ExactRun("("),
    Ident(CV_MODEL),
    ExactRun(","),
    Ident(CV_EFFECTIVE),
    ExactRun(","),
    Ident(CV_ALLOWED),
    ExactRun(") ,"),
    Ident(CV_SELECTED),
    ExactRun("="),
    Ident(CV_REQUEST),
    NullEq,
    ExactRun("? null :"),
    AnyIdent,
    ExactRun("("),
    Ident(CV_MODEL),
    ExactRun(","),
    Ident(CV_REQUEST),
    ExactRun(")"),
];

const ALLOWED_BINDING: &[Atom] = &[ExactRun("isServiceTierAllowed :"), Ident(CV_ALLOWED)];

fn detect_conversation_fallback(tokens: &Tokens<'_>) -> Vec<Site> {
    pattern_sites(
        tokens,
        CONVERSATION_GUARDED,
        CONVERSATION_PATCHED,
        |tokens, hit| {
            let effective = tokens.text(hit.ident(CV_EFFECTIVE));
            let fallback = tokens.text(hit.ident(CV_FALLBACK));
            let model = tokens.text(hit.ident(CV_MODEL));
            let allowed = tokens.text(hit.ident(CV_ALLOWED));
            Some(vec![
                Edit {
                    range: hit.span(tokens, 0)?,
                    replacement: tokens.text(hit.ident(CV_BASE)).to_owned(),
                },
                Edit {
                    range: hit.span(tokens, 1)?,
                    replacement: format!("{fallback}({model},{effective},{allowed})"),
                },
            ])
        },
        conversation_context,
    )
}

fn conversation_context(tokens: &Tokens<'_>, hit: &Hit) -> bool {
    any_in(
        tokens,
        hit.start.saturating_sub(600)..hit.start,
        ALLOWED_BINDING,
        Some(hit),
    ) && has_object_mapping(
        tokens,
        hit.end,
        1800,
        &[
            ("selectedServiceTier", hit.ident(CV_SELECTED)),
            ("serviceTierForRequest", hit.ident(CV_REQUEST)),
        ],
    )
}

const INTELLIGENCE_GUARDED: &[Atom] = &[
    OneOf(&[",", ";"]),
    AnyIdent,
    ExactRun("="),
    Begin(0),
    AnyIdent,
    ExactRun("&&"),
    End(0),
    Ident(0),
    Member("availableOptions"),
    Member("length"),
    ExactRun("> 1 ,"),
];

const INTELLIGENCE_PATCHED: &[Atom] = &[
    OneOf(&[",", ";"]),
    AnyIdent,
    ExactRun("="),
    Ident(0),
    Member("availableOptions"),
    Member("length"),
    ExactRun("> 1 ,"),
];

const INTELLIGENCE_ANCHOR: &[Atom] = &[Str("composer.openModelPicker")];

fn detect_intelligence_menu(tokens: &Tokens<'_>) -> Vec<Site> {
    pattern_sites(
        tokens,
        INTELLIGENCE_GUARDED,
        INTELLIGENCE_PATCHED,
        remove_captured_span,
        intelligence_context,
    )
}

fn intelligence_context(tokens: &Tokens<'_>, hit: &Hit) -> bool {
    any_in(
        tokens,
        hit.end..(hit.end + 64).min(tokens.len()),
        INTELLIGENCE_ANCHOR,
        None,
    )
}

fn detect_slash_command(tokens: &Tokens<'_>) -> Vec<Site> {
    (0..tokens.len())
        .filter(|&index| tokens.text(index) == "requiresEmptyComposer")
        .filter_map(|index| slash_command_at(tokens, index))
        .collect()
}

fn slash_command_at(tokens: &Tokens<'_>, index: usize) -> Option<Site> {
    let object = ObjectView::enclosing(tokens, index)?;
    if bool_value(tokens, object.field(tokens, "requiresEmptyComposer")?) != Some(false) {
        return None;
    }
    let id = single_ident(tokens, object.field(tokens, "id")?)?;
    if !has_service_tier_id(tokens, object, id) {
        return None;
    }
    for key in ["title", "description", "Icon", "onSelect", "dependencies"] {
        single_ident(tokens, object.field(tokens, key)?)?;
    }

    let enabled = object.field(tokens, "enabled")?;
    let edits = if bool_value(tokens, enabled.clone()) == Some(true) {
        Vec::new()
    } else if single_ident(tokens, enabled.clone()).is_some() {
        vec![Edit {
            range: token_range(tokens, enabled.start, enabled.end)?,
            replacement: "!0".to_owned(),
        }]
    } else {
        return None;
    };
    Some(Site {
        range: token_range(tokens, object.open, object.close + 1)?,
        edits,
    })
}

fn has_service_tier_id(tokens: &Tokens<'_>, object: ObjectView, binding: usize) -> bool {
    let Some(scope) = object
        .open
        .checked_sub(1)
        .and_then(|before| enclosing_brace(tokens, before))
    else {
        return false;
    };
    (scope + 1..object.open.saturating_sub(2)).any(|index| {
        tokens.text(index) == tokens.text(binding)
            && tokens.text(index + 1) == "="
            && tokens.kind(index + 2) == Kind::Template
            && tokens.text(index + 2).starts_with("`service-tier:${")
    })
}

#[derive(Clone, Copy)]
struct ObjectView {
    open: usize,
    close: usize,
}

impl ObjectView {
    fn enclosing(tokens: &Tokens<'_>, index: usize) -> Option<Self> {
        let open = enclosing_brace(tokens, index)?;
        Some(Self {
            open,
            close: matching_close(tokens, open)?,
        })
    }

    fn field(self, tokens: &Tokens<'_>, key: &str) -> Option<Range<usize>> {
        let mut result = None;
        let mut start = self.open + 1;
        let mut stack = Vec::new();
        for index in self.open + 1..=self.close {
            let text = tokens.text(index);
            if index == self.close || (text == "," && stack.is_empty()) {
                if start + 2 < index && tokens.text(start) == key && tokens.text(start + 1) == ":" {
                    if result.is_some() {
                        return None;
                    }
                    result = Some(start + 2..index);
                }
                start = index + 1;
            } else {
                update_stack(&mut stack, text)?;
            }
        }
        result
    }
}

fn matching_close(tokens: &Tokens<'_>, open: usize) -> Option<usize> {
    let mut stack = Vec::new();
    for index in open..tokens.len() {
        update_stack(&mut stack, tokens.text(index))?;
        if stack.is_empty() {
            return Some(index);
        }
    }
    None
}

fn enclosing_brace(tokens: &Tokens<'_>, index: usize) -> Option<usize> {
    let mut stack = Vec::new();
    for current in (0..=index).rev() {
        let text = tokens.text(current);
        if let Some(open) = opening_for(text) {
            stack.push(open);
        } else if is_open(text) {
            if stack.last().copied() == Some(text) {
                stack.pop();
            } else if stack.is_empty() {
                if text == "{" {
                    return Some(current);
                }
            } else {
                return None;
            }
        }
    }
    None
}

fn update_stack<'a>(stack: &mut Vec<&'a str>, text: &'a str) -> Option<()> {
    if is_open(text) {
        stack.push(text);
    } else if let Some(open) = opening_for(text) {
        (stack.pop() == Some(open)).then_some(())?;
    }
    Some(())
}

fn is_open(text: &str) -> bool {
    matches!(text, "(" | "[" | "{")
}

fn opening_for(text: &str) -> Option<&'static str> {
    match text {
        ")" => Some("("),
        "]" => Some("["),
        "}" => Some("{"),
        _ => None,
    }
}

fn single_ident(tokens: &Tokens<'_>, range: Range<usize>) -> Option<usize> {
    (range.end == range.start + 1 && tokens.kind(range.start) == Kind::Ident).then_some(range.start)
}

fn bool_value(tokens: &Tokens<'_>, range: Range<usize>) -> Option<bool> {
    let mut position = range.start;
    let value = take_bool_value(tokens, &mut position)?;
    (position == range.end).then_some(value)
}

fn has_object_mapping(
    tokens: &Tokens<'_>,
    start: usize,
    limit: usize,
    expected: &[(&str, usize)],
) -> bool {
    let end = (start + limit).min(tokens.len());
    for index in start..end {
        if tokens.text(index) != expected[0].0 {
            continue;
        }
        let Some(object) = ObjectView::enclosing(tokens, index) else {
            continue;
        };
        if expected.iter().all(|(key, binding)| {
            object
                .field(tokens, key)
                .and_then(|range| single_ident(tokens, range))
                .is_some_and(|value| tokens.text(value) == tokens.text(*binding))
        }) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::planner::apply_edits;

    fn detect(content: &str) -> Vec<(&'static Feature, Vec<Site>)> {
        let tokens = Tokens::new(content);
        FAST_FEATURES
            .iter()
            .filter_map(|feature| {
                let sites = feature
                    .is_active(content)
                    .then(|| feature.detect_sites(&tokens))?;
                (!sites.is_empty()).then_some((feature, sites))
            })
            .collect()
    }

    fn patch(content: &str) -> String {
        let edits = detect(content)
            .into_iter()
            .flat_map(|(_, sites)| sites)
            .flat_map(|site| site.edits)
            .collect::<Vec<_>>();
        apply_edits(content, &edits).unwrap()
    }

    fn assert_legacy_result(anchor: &str, guarded: &str, patched: &str, label: &str) {
        let input = format!("{guarded};`{anchor}`");
        let expected = format!("{patched};`{anchor}`");
        let before = detect(&input);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].0.label, label);
        assert!(before[0].1.iter().all(|site| !site.edits.is_empty()));

        let first = patch(&input);
        assert_eq!(first, expected);
        let after = detect(&first);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0.label, label);
        assert_eq!(after[0].1.len(), before[0].1.len());
        assert!(after[0].1.iter().all(|site| site.edits.is_empty()));
        assert_eq!(patch(&first), first);
    }

    #[test]
    fn speed_setting_matches_legacy_output() {
        assert_legacy_result(
            "settings.agent.speed.label",
            "{isServiceTierAllowed:n}=Je(),{serviceTierSettings:r,setServiceTier:i}=Ye();if(!n||r.availableOptions.length<=1)return null;",
            "{isServiceTierAllowed:n}=Je(),{serviceTierSettings:r,setServiceTier:i}=Ye();if(r.availableOptions.length<=1)return null;",
            "Speed setting",
        );
    }

    #[test]
    fn allowance_matches_legacy_output() {
        let prefix = "let o=a?.authMethod===`chatgpt`,";
        let suffix = "m;return{isServiceTierAllowed:p,isLoading:f}";
        let guarded = "s=a?.authMethod??null,l;t[0]!==i||t[1]!==s?(l={authMethod:s,hostId:i},t[0]=i,t[1]=s,t[2]=l):l=t[2];let{data:u,isPending:d}=r(N,l),f=!!a?.isLoading||o&&d,p=o&&!f&&u!=null&&u?.requirements?.featureRequirements?.fast_mode!==!1,";
        let patched = "s=a?.authMethod??null,l;t[0]!==i||t[1]!==s?(l={authMethod:s,hostId:i},t[0]=i,t[1]=s,t[2]=l):l=t[2];let{data:u,isPending:d}=r(N,l),f=!!a?.isLoading||o&&d,p=!f&&(o?u!=null&&u?.requirements?.featureRequirements?.fast_mode!==!1:!0),";
        assert_legacy_result(
            "fast_mode",
            &format!("{prefix}{guarded}{suffix}"),
            &format!("{prefix}{patched}{suffix}"),
            "Speed service tier allowance",
        );
    }

    #[test]
    fn request_allowance_does_not_depend_on_error_wording() {
        assert_legacy_result(
            "future localized error wording",
            "async function T(e,t){let n=await x(e,t);if(n!==`chatgpt`)return!1;let r=await v(t,{priority:`critical`});return e.query.setData(g,{authMethod:n,hostId:t},r),r.requirements?.featureRequirements?.fast_mode!==!1}",
            "async function T(e,t){let n=await x(e,t);if(n!==`chatgpt`)return!0;let r=await v(t,{priority:`critical`});return e.query.setData(g,{authMethod:n,hostId:t},r),r.requirements?.featureRequirements?.fast_mode!==!1}",
            "Speed service tier request allowance",
        );
    }

    #[test]
    fn request_allowance_rejects_line_break_after_return() {
        let input = format!(
            "{};{}",
            "async function e(t,n){let r=await i(t,n);if(r!==`chatgpt`)return\n!1;let a=await o(n,{priority:`critical`});return t.query.setData(s,{authMethod:r,hostId:n},a),a.requirements?.featureRequirements?.fast_mode!==!1}",
            "`Failed to read service tier for request`"
        );

        assert!(detect(&input).is_empty());
    }

    #[test]
    fn conversation_fallback_matches_legacy_output() {
        let before = "{isServiceTierAllowed:M}=J(j);let r=H(p?.models,t.model),i=x?.requirements?.models?.newThread,s=e==null&&a&&i!=null,d=s?i.serviceTier:null,y=d!=null,b=e==null&&n!=null?n.value:y?O(d):C.serviceTier,E=e!=null&&h?.serviceTier!==void 0?h.serviceTier:e!=null&&v!==void 0?v:b;I=e!=null&&(h?.serviceTier!==void 0||v!==void 0)?M?E:null:D(r,E,M),F=I==null?null:_(r,I);let U={selectedServiceTier:F,serviceTierForRequest:I}";
        let after = "{isServiceTierAllowed:M}=J(j);let r=H(p?.models,t.model),i=x?.requirements?.models?.newThread,s=e==null&&a&&i!=null,d=s?i.serviceTier:null,y=d!=null,b=e==null&&n!=null?n.value:y?O(d):C.serviceTier,E=b;I=D(r,E,M),F=I==null?null:_(r,I);let U={selectedServiceTier:F,serviceTierForRequest:I}";
        assert_legacy_result(
            "serviceTierForRequest",
            before,
            after,
            "Speed service tier conversation fallback",
        );
    }

    #[test]
    fn conversation_fallback_requires_the_legacy_base_tier_shape() {
        let body = "{isServiceTierAllowed:M}=J(j);let b=unrelated(),E=e!=null&&h?.serviceTier!==void 0?h.serviceTier:e!=null&&v!==void 0?v:b;I=e!=null&&(h?.serviceTier!==void 0||v!==void 0)?M?E:null:D(r,E,M),F=I==null?null:_(r,I);let U={selectedServiceTier:F,serviceTierForRequest:I};`selectedServiceTier`;`serviceTierForRequest`";

        assert!(detect(body).is_empty());
    }

    #[test]
    fn intelligence_menu_matches_legacy_output() {
        assert_legacy_result(
            "composer.openModelPicker",
            ",pe=O&&E.availableOptions.length>1,",
            ",pe=E.availableOptions.length>1,",
            "Composer Intelligence Speed menu",
        );
    }

    #[test]
    fn intelligence_menu_requires_a_nearby_command_anchor() {
        let body = format!(
            ",pe=O&&E.availableOptions.length>1,{} `composer.openModelPicker`",
            "x=0;".repeat(80)
        );

        assert!(detect(&body).is_empty());
    }

    #[test]
    fn slash_command_matches_legacy_output() {
        assert_legacy_result(
            "composer.speedSlashCommand.disableDescription",
            "function f(){l=`service-tier:${a}`;g={id:l,title:u,description:d,requiresEmptyComposer:!1,enabled:n,Icon:c,onSelect:m,dependencies:h};return g}",
            "function f(){l=`service-tier:${a}`;g={id:l,title:u,description:d,requiresEmptyComposer:!1,enabled:!0,Icon:c,onSelect:m,dependencies:h};return g}",
            "Fast slash command",
        );
    }

    #[test]
    fn repeated_anchor_tokens_identify_one_slash_command_site() {
        assert_legacy_result(
            "composer.speedSlashCommand.disableDescription",
            "function f(){l=`service-tier:${a}`;g={id:l,title:u,description:d,requiresEmptyComposer:!1,enabled:requiresEmptyComposer,Icon:c,onSelect:m,dependencies:h};return g}",
            "function f(){l=`service-tier:${a}`;g={id:l,title:u,description:d,requiresEmptyComposer:!1,enabled:!0,Icon:c,onSelect:m,dependencies:h};return g}",
            "Fast slash command",
        );
    }

    #[test]
    fn token_matching_ignores_formatting_and_variable_names() {
        let input = r#"
            "settings.agent.speed.label";
            { isServiceTierAllowed: allowed } = useAllowance(),
            { serviceTierSettings: settings, setServiceTier: setTier } = useSettings();
            if ( ! allowed /* keep comments harmless */ || settings.availableOptions.length <= 1 )
                return null;
        "#;
        let result = patch(input);
        assert!(result.contains("if (  settings.availableOptions"));
    }

    #[test]
    fn decoys_in_literals_comments_and_regexes_are_ignored() {
        let body = r#"
            "settings.agent.speed.label";
            const text = "{isServiceTierAllowed:n}=x(),{serviceTierSettings:r,setServiceTier:i}=y();if(!n||r.availableOptions.length<=1)return null;";
            /* {isServiceTierAllowed:n}=x(),{serviceTierSettings:r,setServiceTier:i}=y();if(!n||r.availableOptions.length<=1)return null; */
            const pattern = /if\(!n\|\|r\.availableOptions\.length<=1\)/;
        "#;
        assert!(detect(body).is_empty());
    }

    #[test]
    fn multiple_sites_are_patched_together() {
        let target = "{isServiceTierAllowed:n}=Je(),{serviceTierSettings:r,setServiceTier:i}=Ye();if(!n||r.availableOptions.length<=1)return null;";
        let body = format!("`settings.agent.speed.label`;{target}{target}");
        let result = patch(&body);

        assert_eq!(result.matches("if(r.availableOptions").count(), 2);
        let after = detect(&result);
        assert_eq!(after[0].1.len(), 2);
        assert!(after[0].1.iter().all(|site| site.edits.is_empty()));
    }
}

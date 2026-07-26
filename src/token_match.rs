use std::ops::Range;

use crate::js_tokens::{Kind, Tokens};

const ID_SLOTS: usize = 16;
const SPAN_SLOTS: usize = 4;
const BOOL_SLOTS: usize = 4;

#[derive(Clone, Copy)]
pub enum Atom {
    ExactRun(&'static str),
    OneOf(&'static [&'static str]),
    AnyIdent,
    Ident(usize),
    Str(&'static str),
    Bool(bool),
    CaptureBool(usize),
    Member(&'static str),
    NullEq,
    NullNe,
    Undefined,
    NoLineBreak,
    Begin(usize),
    End(usize),
}

#[derive(Clone)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    ids: [Option<usize>; ID_SLOTS],
    spans: [Option<(usize, usize)>; SPAN_SLOTS],
    bools: [Option<bool>; BOOL_SLOTS],
}

impl Hit {
    pub fn ident(&self, slot: usize) -> usize {
        self.ids[slot].expect("matched identifier slot")
    }

    pub fn span(&self, tokens: &Tokens<'_>, slot: usize) -> Option<Range<usize>> {
        let (start, end) = self.spans[slot]?;
        token_range(tokens, start, end)
    }

    pub fn boolean(&self, slot: usize) -> bool {
        self.bools[slot].expect("matched boolean slot")
    }
}

pub fn find<'a>(tokens: &'a Tokens<'_>, pattern: &'a [Atom]) -> impl Iterator<Item = Hit> + 'a {
    let pivot = literal_pivot(pattern);
    (0..tokens.len())
        .filter(move |&start| pivot.is_none_or(|pivot| pivot.matches(tokens, start)))
        .filter_map(move |start| match_at_with(tokens, start, pattern, None))
}

pub fn any_in(
    tokens: &Tokens<'_>,
    range: Range<usize>,
    pattern: &[Atom],
    seed: Option<&Hit>,
) -> bool {
    let pivot = literal_pivot(pattern);
    range
        .into_iter()
        .filter(|&start| pivot.is_none_or(|pivot| pivot.matches(tokens, start)))
        .any(|start| match_at_with(tokens, start, pattern, seed).is_some())
}

#[derive(Clone, Copy)]
struct Pivot {
    offset: usize,
    text: &'static str,
}

impl Pivot {
    fn matches(self, tokens: &Tokens<'_>, start: usize) -> bool {
        start
            .checked_add(self.offset)
            .is_some_and(|index| index < tokens.len() && tokens.text(index) == self.text)
    }
}

fn literal_pivot(pattern: &[Atom]) -> Option<Pivot> {
    let mut offset = 0;
    let mut best = None;

    for atom in pattern {
        match *atom {
            Atom::ExactRun(expected) => {
                for text in expected.split_ascii_whitespace() {
                    consider_pivot(&mut best, offset, text);
                    offset += 1;
                }
            }
            Atom::Member(property) => {
                offset += 1;
                consider_pivot(&mut best, offset, property);
                offset += 1;
            }
            Atom::NullEq | Atom::NullNe => {
                offset += 1;
                consider_pivot(&mut best, offset, "null");
                offset += 1;
            }
            Atom::OneOf(_) | Atom::AnyIdent | Atom::Ident(_) | Atom::Str(_) => offset += 1,
            Atom::Bool(_) | Atom::CaptureBool(_) | Atom::Undefined => break,
            Atom::NoLineBreak | Atom::Begin(_) | Atom::End(_) => {}
        }
    }
    best
}

fn consider_pivot(best: &mut Option<Pivot>, offset: usize, text: &'static str) {
    if best.is_none_or(|pivot| text.len() > pivot.text.len()) {
        *best = Some(Pivot { offset, text });
    }
}

#[cfg(test)]
pub fn match_at(tokens: &Tokens<'_>, start: usize, pattern: &[Atom]) -> Option<Hit> {
    match_at_with(tokens, start, pattern, None)
}

fn match_at_with(
    tokens: &Tokens<'_>,
    start: usize,
    pattern: &[Atom],
    seed: Option<&Hit>,
) -> Option<Hit> {
    let mut position = start;
    let mut ids = seed.map_or([None; ID_SLOTS], |hit| hit.ids);
    let mut spans = [None; SPAN_SLOTS];
    let mut bools = [None; BOOL_SLOTS];

    for atom in pattern {
        match *atom {
            Atom::ExactRun(expected) => {
                for token in expected.split_ascii_whitespace() {
                    take(tokens, &mut position, token)?;
                }
            }
            Atom::OneOf(expected) => take_one(tokens, &mut position, expected)?,
            Atom::AnyIdent => {
                take_ident(tokens, &mut position)?;
            }
            Atom::Ident(slot) => {
                let index = take_ident(tokens, &mut position)?;
                match ids.get_mut(slot)? {
                    Some(bound) if tokens.text(*bound) != tokens.text(index) => return None,
                    bound @ None => *bound = Some(index),
                    _ => {}
                }
            }
            Atom::Str(expected) => {
                (position < tokens.len()).then_some(())?;
                tokens.string_eq(position, expected).then_some(())?;
                position += 1;
            }
            Atom::Bool(expected) => take_bool(tokens, &mut position, expected)?,
            Atom::CaptureBool(slot) => {
                let value = take_bool_value(tokens, &mut position)?;
                let captured = bools.get_mut(slot)?;
                match captured {
                    Some(bound) if *bound != value => return None,
                    captured @ None => *captured = Some(value),
                    _ => {}
                }
            }
            Atom::Member(property) => {
                take_one(tokens, &mut position, &[".", "?."])?;
                take(tokens, &mut position, property)?;
            }
            Atom::NullEq => {
                take_one(tokens, &mut position, &["==", "==="])?;
                take(tokens, &mut position, "null")?;
            }
            Atom::NullNe => {
                take_one(tokens, &mut position, &["!=", "!=="])?;
                take(tokens, &mut position, "null")?;
            }
            Atom::Undefined => {
                if take(tokens, &mut position, "undefined").is_none() {
                    take(tokens, &mut position, "void")?;
                    take(tokens, &mut position, "0")?;
                }
            }
            Atom::NoLineBreak => {
                (position < tokens.len() && !tokens.has_line_break_before(position))
                    .then_some(())?;
            }
            Atom::Begin(slot) => {
                let span = spans.get_mut(slot)?;
                span.is_none().then_some(())?;
                *span = Some((position, position));
            }
            Atom::End(slot) => {
                let span = spans.get_mut(slot)?.as_mut()?;
                (span.0 < position && span.1 == span.0).then_some(())?;
                span.1 = position;
            }
        }
    }

    Some(Hit {
        start,
        end: position,
        ids,
        spans,
        bools,
    })
}

pub fn token_range(tokens: &Tokens<'_>, start: usize, end: usize) -> Option<Range<usize>> {
    (start < end && end <= tokens.len()).then(|| tokens.span(start).start..tokens.span(end - 1).end)
}

fn take(tokens: &Tokens<'_>, position: &mut usize, expected: &str) -> Option<()> {
    (*position < tokens.len()).then_some(())?;
    (tokens.text(*position) == expected).then_some(())?;
    *position += 1;
    Some(())
}

fn take_one(tokens: &Tokens<'_>, position: &mut usize, expected: &[&str]) -> Option<()> {
    (*position < tokens.len()).then_some(())?;
    expected.contains(&tokens.text(*position)).then_some(())?;
    *position += 1;
    Some(())
}

fn take_ident(tokens: &Tokens<'_>, position: &mut usize) -> Option<usize> {
    let index = *position;
    (index < tokens.len()).then_some(())?;
    (tokens.kind(index) == Kind::Ident).then_some(())?;
    *position += 1;
    Some(index)
}

fn take_bool(tokens: &Tokens<'_>, position: &mut usize, expected: bool) -> Option<()> {
    (take_bool_value(tokens, position)? == expected).then_some(())
}

pub(crate) fn take_bool_value(tokens: &Tokens<'_>, position: &mut usize) -> Option<bool> {
    (*position < tokens.len()).then_some(())?;
    match tokens.text(*position) {
        "true" => {
            *position += 1;
            Some(true)
        }
        "false" => {
            *position += 1;
            Some(false)
        }
        "!" => {
            *position += 1;
            (*position < tokens.len()).then_some(())?;
            let value = match tokens.text(*position) {
                "0" => true,
                "1" => false,
                _ => return None,
            };
            *position += 1;
            Some(value)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Atom::*;

    #[test]
    fn binds_identifiers_and_marks_a_span() {
        let source = "if (!allowed || settings.availableOptions.length <= 1)";
        let tokens = Tokens::new(source);
        let pattern = &[
            ExactRun("if ("),
            Begin(0),
            ExactRun("!"),
            Ident(0),
            ExactRun("||"),
            End(0),
            Ident(1),
            Member("availableOptions"),
            Member("length"),
            ExactRun("<= 1 )"),
        ];
        let hit = match_at(&tokens, 0, pattern).unwrap();
        assert_eq!(&tokens.span(hit.ident(0)), &(5..12));
        assert_eq!(&tokens.span(hit.ident(1)), &(16..24));
        assert_eq!(tokens.span(0), 0..2);
        assert_eq!(tokens.span(tokens.len() - 1), 53..54);
        assert_eq!(tokens.span(hit.start), 0..2);
        assert_eq!(hit.end, tokens.len());
        assert_eq!(&source[hit.span(&tokens, 0).unwrap()], "!allowed ||");
    }

    #[test]
    fn truncated_input_fails_without_panicking() {
        let tokens = Tokens::new("x");
        assert!(match_at(&tokens, 0, &[ExactRun("x"), OneOf(&["y"])]).is_none());
        assert!(match_at(&tokens, 0, &[ExactRun("x"), Str("y")]).is_none());
        assert!(match_at(&tokens, 0, &[ExactRun("x"), CaptureBool(0)]).is_none());
    }

    #[test]
    fn pivot_filter_matches_exhaustive_search() {
        let tokens = Tokens::new("skip;let value=owner?.feature===null;tail");
        let pattern = &[
            ExactRun("let"),
            AnyIdent,
            ExactRun("="),
            AnyIdent,
            Member("feature"),
            NullEq,
            ExactRun(";"),
        ];
        let optimized = find(&tokens, pattern)
            .map(|hit| (hit.start, hit.end))
            .collect::<Vec<_>>();
        let exhaustive = (0..tokens.len())
            .filter_map(|start| match_at_with(&tokens, start, pattern, None))
            .map(|hit| (hit.start, hit.end))
            .collect::<Vec<_>>();

        assert_eq!(optimized, exhaustive);
        assert_eq!(optimized.len(), 1);
    }

    #[test]
    fn pivot_never_crosses_variable_width_atoms() {
        for source in ["true rare", "!0 rare"] {
            assert_eq!(
                find(&Tokens::new(source), &[Bool(true), ExactRun("rare")]).count(),
                1
            );
        }
        for source in ["undefined rare", "void 0 rare"] {
            assert_eq!(
                find(&Tokens::new(source), &[Undefined, ExactRun("rare")]).count(),
                1
            );
        }
        for source in ["false rare", "!1 rare"] {
            assert_eq!(
                find(&Tokens::new(source), &[CaptureBool(0), ExactRun("rare")]).count(),
                1
            );
        }
    }
}

use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Ident,
    Number,
    String,
    Template,
    Regex,
    Punct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
    line_break_before: bool,
    closes_control_header: bool,
    closes_statement_block: bool,
}

#[derive(Default)]
struct DelimiterState {
    control_headers: Vec<bool>,
    statement_blocks: Vec<bool>,
}

pub struct Tokens<'s> {
    source: &'s str,
    items: Vec<Token>,
}

impl<'s> Tokens<'s> {
    pub fn new(source: &'s str) -> Self {
        let mut items = Vec::new();
        let mut delimiters = DelimiterState::default();
        let mut position = 0;

        while let Some(token) = next_token(
            source,
            &mut position,
            items.last().copied(),
            &mut delimiters,
        ) {
            items.push(token);
        }

        Self { source, items }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn kind(&self, index: usize) -> Kind {
        self.items[index].kind
    }

    pub fn text(&self, index: usize) -> &'s str {
        let token = self.items[index];
        &self.source[token.start..token.end]
    }

    pub fn span(&self, index: usize) -> Range<usize> {
        let token = self.items[index];
        token.start..token.end
    }

    pub fn string_eq(&self, index: usize, expected: &str) -> bool {
        let token = self.items[index];
        if !matches!(token.kind, Kind::String | Kind::Template) {
            return false;
        }
        literal_eq(&self.source[token.start..token.end], expected)
    }

    pub fn has_line_break_before(&self, index: usize) -> bool {
        self.items[index].line_break_before
    }
}

fn next_char(source: &str, position: usize) -> char {
    source[position..].chars().next().unwrap()
}

fn next_token(
    source: &str,
    position: &mut usize,
    previous: Option<Token>,
    delimiters: &mut DelimiterState,
) -> Option<Token> {
    let mut line_break_before = false;
    loop {
        if *position >= source.len() {
            return None;
        }
        if let Some(end) = trivia_end(source, *position) {
            line_break_before |= source[*position..end].chars().any(is_line_terminator);
            *position = end;
            continue;
        }

        let mut token = token_at(source, *position, previous);
        token.line_break_before = line_break_before;
        let token = annotate_delimiters(source, previous, delimiters, token);
        *position = token.end;
        return Some(token);
    }
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphabetic() || (!ch.is_ascii() && !ch.is_whitespace())
}

fn ident_end(source: &str, mut position: usize) -> usize {
    while position < source.len() {
        let ch = next_char(source, position);
        if !is_ident_start(ch) && !ch.is_ascii_digit() {
            break;
        }
        position += ch.len_utf8();
    }
    position
}

fn number_end(source: &str, position: usize) -> usize {
    let bytes = source.as_bytes();
    if bytes[position] == b'0' && position + 1 < bytes.len() {
        let radix = match bytes[position + 1] {
            b'x' | b'X' => Some(16),
            b'o' | b'O' => Some(8),
            b'b' | b'B' => Some(2),
            _ => None,
        };
        if let Some(radix) = radix {
            let end = digits_end(bytes, position + 2, radix);
            return end + usize::from(bytes.get(end) == Some(&b'n'));
        }
    }

    let mut end = if bytes[position] == b'.' {
        digits_end(bytes, position + 1, 10)
    } else {
        digits_end(bytes, position, 10)
    };
    let mut fractional = bytes[position] == b'.';
    if !fractional && bytes.get(end) == Some(&b'.') {
        fractional = true;
        end = digits_end(bytes, end + 1, 10);
    }
    let mut exponent = false;
    if matches!(bytes.get(end), Some(b'e' | b'E')) {
        exponent = true;
        end += 1;
        if matches!(bytes.get(end), Some(b'+' | b'-')) {
            end += 1;
        }
        end = digits_end(bytes, end, 10);
    }
    end + usize::from(!fractional && !exponent && bytes.get(end) == Some(&b'n'))
}

fn digits_end(bytes: &[u8], mut position: usize, radix: u32) -> usize {
    while let Some(&byte) = bytes.get(position) {
        if byte != b'_' && !char::from(byte).is_digit(radix) {
            break;
        }
        position += 1;
    }
    position
}

fn quoted_end(source: &str, start: usize, quote: char) -> usize {
    let mut position = start + 1;
    while position < source.len() {
        let ch = next_char(source, position);
        match ch {
            '\\' => position = escaped_end(source, position),
            ch if ch == quote => return position + 1,
            '\r' | '\n' => return position,
            _ => position += ch.len_utf8(),
        }
    }
    position
}

fn escaped_end(source: &str, position: usize) -> usize {
    let Some(escaped) = source[position + 1..].chars().next() else {
        return source.len();
    };
    let end = position + 1 + escaped.len_utf8();
    end + usize::from(escaped == '\r' && source[end..].starts_with('\n'))
}

fn template_end(source: &str, start: usize) -> usize {
    let mut position = start + 1;
    while position < source.len() {
        let ch = next_char(source, position);
        match ch {
            '\\' => position = escaped_end(source, position),
            '`' => return position + 1,
            '$' if source[position + 1..].starts_with('{') => {
                position = template_expression_end(source, position + 2)
            }
            _ => position += ch.len_utf8(),
        }
    }
    position
}

fn template_expression_end(source: &str, mut position: usize) -> usize {
    let mut depth = 1;
    let mut previous = None;
    let mut delimiters = DelimiterState::default();
    while let Some(token) = next_token(source, &mut position, previous, &mut delimiters) {
        if token.kind == Kind::Punct {
            match &source[token.start..token.end] {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        return position;
                    }
                }
                _ => {}
            }
        }
        previous = Some(token);
    }
    position
}

fn token_at(source: &str, start: usize, previous: Option<Token>) -> Token {
    let ch = next_char(source, start);
    let (kind, end) = match ch {
        '\'' | '"' => (Kind::String, quoted_end(source, start, ch)),
        '`' => (Kind::Template, template_end(source, start)),
        '/' if regex_allowed(source, previous) => (Kind::Regex, regex_end(source, start)),
        ch if is_ident_start(ch) => (Kind::Ident, ident_end(source, start)),
        ch if ch.is_ascii_digit()
            || (ch == '.'
                && source[start + 1..]
                    .chars()
                    .next()
                    .is_some_and(|next| next.is_ascii_digit())) =>
        {
            (Kind::Number, number_end(source, start))
        }
        _ => (Kind::Punct, operator_end(source, start)),
    };
    Token {
        kind,
        start,
        end,
        line_break_before: false,
        closes_control_header: false,
        closes_statement_block: false,
    }
}

fn annotate_delimiters(
    source: &str,
    previous: Option<Token>,
    state: &mut DelimiterState,
    mut token: Token,
) -> Token {
    if token.kind != Kind::Punct {
        return token;
    }
    match &source[token.start..token.end] {
        "(" => state.control_headers.push(previous.is_some_and(|token| {
            token.kind == Kind::Ident && is_control_keyword(&source[token.start..token.end])
        })),
        ")" => token.closes_control_header = state.control_headers.pop().unwrap_or(false),
        "{" => state
            .statement_blocks
            .push(starts_statement_block(source, previous, state)),
        "}" => token.closes_statement_block = state.statement_blocks.pop().unwrap_or(false),
        _ => {}
    }
    token
}

fn starts_statement_block(source: &str, previous: Option<Token>, state: &DelimiterState) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let text = &source[previous.start..previous.end];
    match previous.kind {
        Kind::Ident => matches!(text, "catch" | "do" | "else" | "finally" | "static" | "try"),
        Kind::Punct => match text {
            ")" | "=>" | ";" => true,
            "{" => state.statement_blocks.last().copied().unwrap_or(true),
            _ => false,
        },
        _ => false,
    }
}

fn regex_allowed(source: &str, previous: Option<Token>) -> bool {
    let Some(previous) = previous else {
        return true;
    };
    let text = &source[previous.start..previous.end];
    match previous.kind {
        Kind::Ident => regex_after_ident(text),
        Kind::Punct if text == "}" => previous.closes_statement_block,
        Kind::Punct => regex_after_punct(text) || previous.closes_control_header,
        Kind::Number | Kind::String | Kind::Template | Kind::Regex => false,
    }
}

fn is_control_keyword(ident: &str) -> bool {
    matches!(ident, "if" | "while" | "for" | "with" | "switch" | "catch")
}

fn regex_after_ident(ident: &str) -> bool {
    matches!(
        ident,
        "await"
            | "case"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "in"
            | "instanceof"
            | "new"
            | "of"
            | "return"
            | "throw"
            | "typeof"
            | "void"
            | "yield"
    )
}

fn regex_after_punct(punct: &str) -> bool {
    !matches!(punct, ")" | "]" | "}" | "++" | "--" | "." | "?.")
}

fn regex_end(source: &str, start: usize) -> usize {
    let mut position = start + 1;
    let mut in_class = false;
    while position < source.len() {
        let ch = next_char(source, position);
        match ch {
            '\\' => position = escaped_end(source, position),
            '[' => {
                in_class = true;
                position += 1;
            }
            ']' => {
                in_class = false;
                position += 1;
            }
            '/' if !in_class => {
                position += 1;
                while position < source.len() {
                    let flag = next_char(source, position);
                    if !flag.is_ascii_alphabetic() {
                        break;
                    }
                    position += 1;
                }
                return position;
            }
            ch if is_line_terminator(ch) => return position,
            _ => position += ch.len_utf8(),
        }
    }
    position
}

fn line_comment_end(source: &str, mut position: usize) -> usize {
    while position < source.len() {
        let ch = next_char(source, position);
        if is_line_terminator(ch) {
            break;
        }
        position += ch.len_utf8();
    }
    position
}

fn is_line_terminator(ch: char) -> bool {
    matches!(ch, '\r' | '\n' | '\u{2028}' | '\u{2029}')
}

fn trivia_end(source: &str, position: usize) -> Option<usize> {
    let ch = next_char(source, position);
    if ch.is_whitespace() {
        Some(position + ch.len_utf8())
    } else if source[position..].starts_with("//") {
        Some(line_comment_end(source, position + 2))
    } else if source[position..].starts_with("/*") {
        Some(block_comment_end(source, position + 2))
    } else {
        None
    }
}

fn block_comment_end(source: &str, position: usize) -> usize {
    source[position..]
        .find("*/")
        .map_or(source.len(), |offset| position + offset + 2)
}

fn operator_end(source: &str, position: usize) -> usize {
    const OPERATORS: &[&str] = &[
        ">>>=", "===", "!==", ">>>", "**=", "&&=", "||=", "??=", "<<=", ">>=", "...", "=>", "==",
        "!=", "<=", ">=", "++", "--", "&&", "||", "??", "?.", "**", "<<", ">>", "+=", "-=", "*=",
        "/=", "%=", "&=", "|=", "^=",
    ];
    OPERATORS
        .iter()
        .find(|operator| source[position..].starts_with(**operator))
        .map_or_else(
            || position + next_char(source, position).len_utf8(),
            |operator| position + operator.len(),
        )
}

fn literal_eq(raw: &str, expected: &str) -> bool {
    let Some(quote) = raw.chars().next() else {
        return false;
    };
    if raw.len() < 2 || !raw.ends_with(quote) {
        return false;
    }
    let inner = &raw[1..raw.len() - 1];
    if !inner.contains('\\') {
        return !(quote == '`' && inner.contains("${")) && inner == expected;
    }

    let mut chars = inner.chars();
    let mut decoded = String::with_capacity(inner.len());
    while let Some(ch) = chars.next() {
        if quote == '`' && ch == '$' && chars.as_str().starts_with('{') {
            return false;
        }
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return false;
        };
        match escaped {
            '\r' => {
                if chars.as_str().starts_with('\n') {
                    chars.next();
                }
            }
            '\n' | '\u{2028}' | '\u{2029}' => {}
            '0' => decoded.push('\0'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000b}'),
            'x' => match hex_escape(&mut chars, 2) {
                Some(ch) => decoded.push(ch),
                None => return false,
            },
            'u' => match unicode_escape(&mut chars) {
                Some(ch) => decoded.push(ch),
                None => return false,
            },
            other => decoded.push(other),
        }
    }
    decoded == expected
}

fn unicode_escape(chars: &mut std::str::Chars<'_>) -> Option<char> {
    if !chars.as_str().starts_with('{') {
        return hex_escape(chars, 4);
    }
    chars.next();
    let digits = chars.as_str().find('}')?;
    let value = u32::from_str_radix(chars.as_str().get(..digits)?, 16).ok()?;
    chars.nth(digits)?;
    char::from_u32(value)
}

fn hex_escape(chars: &mut std::str::Chars<'_>, digits: usize) -> Option<char> {
    let raw = chars.as_str().get(..digits)?;
    let value = u32::from_str_radix(raw, 16).ok()?;
    chars.nth(digits - 1)?;
    char::from_u32(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts<'a>(tokens: &'a Tokens<'a>) -> Vec<&'a str> {
        (0..tokens.len()).map(|index| tokens.text(index)).collect()
    }

    #[test]
    fn skips_comments_without_mistaking_strings_for_comments() {
        let tokens = Tokens::new(
            r#"const text="// if(fake)return false"; /* fake() */ real=!1;// fake2()
next()"#,
        );
        assert_eq!(
            texts(&tokens),
            [
                "const",
                "text",
                "=",
                r#""// if(fake)return false""#,
                ";",
                "real",
                "=",
                "!",
                "1",
                ";",
                "next",
                "(",
                ")",
            ]
        );
    }

    #[test]
    fn keeps_nested_interpolated_template_opaque() {
        let source = r#"before;`outer ${fn({value:`inner ${/}/.test("}")}`})} tail`;after()"#;
        let tokens = Tokens::new(source);
        let templates = (0..tokens.len())
            .filter(|&index| tokens.kind(index) == Kind::Template)
            .collect::<Vec<_>>();
        assert_eq!(templates.len(), 1);
        assert!(tokens.text(templates[0]).contains("inner"));
        assert_eq!(&texts(&tokens)[tokens.len() - 3..], ["after", "(", ")"]);
    }

    #[test]
    fn regex_body_does_not_emit_fake_code() {
        let tokens = Tokens::new(r#"const r=/if\(x\)return false;[{}\/]/gi;real=false"#);
        let regex = (0..tokens.len())
            .find(|&index| tokens.kind(index) == Kind::Regex)
            .unwrap();
        assert_eq!(tokens.text(regex), r#"/if\(x\)return false;[{}\/]/gi"#);
        assert_eq!(
            texts(&tokens)
                .iter()
                .filter(|&&text| text == "return")
                .count(),
            0
        );
    }

    #[test]
    fn distinguishes_division_from_regex_literals() {
        let tokens = Tokens::new("let ratio=a/b/c; return /a\\/b/g.test(value)");
        assert_eq!(
            (0..tokens.len())
                .filter(|&index| tokens.kind(index) == Kind::Punct && tokens.text(index) == "/")
                .count(),
            2
        );
        assert_eq!(
            (0..tokens.len())
                .filter(|&index| tokens.kind(index) == Kind::Regex)
                .count(),
            1
        );
    }

    #[test]
    fn unicode_input_is_safe() {
        let tokens = Tokens::new("const π='你好';let 😀=`值 ${π/2}`;结束?.调用()");
        assert!(texts(&tokens).contains(&"π"));
        let pi = (0..tokens.len())
            .find(|&index| tokens.text(index) == "π")
            .unwrap();
        assert_eq!(&tokens.source[tokens.span(pi)], "π");
    }

    #[test]
    fn compares_literal_values() {
        let tokens = Tokens::new(
            r#"name "fast mode" name `fast` `fast ${mode}` "chat\u0067pt" '\x66ast' `literal \${value}` "\u{1f600}""#,
        );
        assert!(tokens.string_eq(1, "fast mode"));
        assert!(tokens.string_eq(3, "fast"));
        assert!(!tokens.string_eq(4, "fast"));
        assert!(tokens.string_eq(5, "chatgpt"));
        assert!(tokens.string_eq(6, "fast"));
        assert!(tokens.string_eq(7, "literal ${value}"));
        assert!(tokens.string_eq(8, "😀"));
    }

    #[test]
    fn recognizes_all_javascript_line_terminators() {
        let tokens = Tokens::new("// hidden\u{2028}visible;// hidden\u{2029}again");
        assert_eq!(texts(&tokens), ["visible", ";", "again"]);
    }

    #[test]
    fn recognizes_regex_after_control_header() {
        let tokens = Tokens::new("if(ok)/return false;}/.test(value);real=!1");
        assert_eq!(
            (0..tokens.len())
                .filter(|&index| tokens.kind(index) == Kind::Regex)
                .map(|index| tokens.text(index))
                .collect::<Vec<_>>(),
            ["/return false;}/"]
        );
        assert!(!texts(&tokens).contains(&"return"));
    }

    #[test]
    fn recognizes_regex_after_a_statement_block() {
        let tokens = Tokens::new("if(ok){} /,x=y&&z.availableOptions.length>1,/.test(value)");

        assert!((0..tokens.len()).all(|index| tokens.text(index) != "availableOptions"));
        assert!((0..tokens.len()).any(|index| tokens.kind(index) == Kind::Regex));
    }

    #[test]
    fn recognizes_regex_after_export_default() {
        let tokens = Tokens::new("export default /,x=y&&z.availableOptions.length>1,/;visible=!1");

        assert!((0..tokens.len()).any(|index| tokens.kind(index) == Kind::Regex));
        assert!((0..tokens.len()).all(|index| tokens.text(index) != "availableOptions"));
    }

    #[test]
    fn keeps_division_after_an_object_literal_visible() {
        let tokens =
            Tokens::new("const x={}/(q,target=gate&&settings.availableOptions.length>1,r)/z");

        assert_eq!(
            (0..tokens.len())
                .filter(|&index| tokens.kind(index) == Kind::Regex)
                .count(),
            0
        );
        assert!(texts(&tokens).contains(&"availableOptions"));
    }

    #[test]
    fn keeps_unicode_separators_inside_strings() {
        let tokens =
            Tokens::new("\"prefix\u{2028},x=y&&z.availableOptions.length>1,suffix\";visible");

        assert_eq!(tokens.kind(0), Kind::String);
        assert_eq!(
            texts(&tokens),
            [
                "\"prefix\u{2028},x=y&&z.availableOptions.length>1,suffix\"",
                ";",
                "visible"
            ]
        );
    }
}

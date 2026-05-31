use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl JsonError {
    fn new(message: impl Into<String>, line: usize, column: usize) -> Self {
        Self {
            message: message.into(),
            line,
            column,
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at line {}, column {}", self.message, self.line, self.column)
    }
}

impl std::error::Error for JsonError {}

pub fn parse_json(input: &str) -> Result<JsonValue, JsonError> {
    let mut parser = Parser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if !parser.is_eof() {
        return Err(parser.error("trailing characters"));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a str,
    index: usize,
    line: usize,
    column: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            index: 0,
            line: 1,
            column: 1,
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        match self.peek_char() {
            Some('n') => self.parse_null(),
            Some('t') | Some('f') => self.parse_bool(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-') | Some('0'..='9') => self.parse_number(),
            Some(_) => Err(self.error("unexpected character while parsing value")),
            None => Err(self.error("unexpected end of input while parsing value")),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, JsonError> {
        self.consume_literal("null")?;
        Ok(JsonValue::Null)
    }

    fn parse_bool(&mut self) -> Result<JsonValue, JsonError> {
        if self.try_consume_literal("true") {
            Ok(JsonValue::Bool(true))
        } else if self.try_consume_literal("false") {
            Ok(JsonValue::Bool(false))
        } else {
            Err(self.error("invalid boolean literal"))
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.index;

        if self.peek_char() == Some('-') {
            self.advance_char();
        }

        match self.peek_char() {
            Some('0') => {
                self.advance_char();
                if matches!(self.peek_char(), Some('0'..='9')) {
                    return Err(self.error("leading zeros are not allowed"));
                }
            }
            Some('1'..='9') => {
                self.advance_char();
                while matches!(self.peek_char(), Some('0'..='9')) {
                    self.advance_char();
                }
            }
            _ => return Err(self.error("invalid number")),
        }

        if self.peek_char() == Some('.') {
            self.advance_char();
            let mut digits = 0usize;
            while matches!(self.peek_char(), Some('0'..='9')) {
                self.advance_char();
                digits += 1;
            }
            if digits == 0 {
                return Err(self.error("expected digits after decimal point"));
            }
        }

        if matches!(self.peek_char(), Some('e') | Some('E')) {
            self.advance_char();
            if matches!(self.peek_char(), Some('+') | Some('-')) {
                self.advance_char();
            }
            let mut digits = 0usize;
            while matches!(self.peek_char(), Some('0'..='9')) {
                self.advance_char();
                digits += 1;
            }
            if digits == 0 {
                return Err(self.error("expected digits in exponent"));
            }
        }

        let number = &self.input[start..self.index];
        match number.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(JsonValue::Number(value)),
            Ok(_) => Err(self.error("number is not finite")),
            Err(_) => Err(self.error("invalid number")),
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect_char('"')?;
        let mut out = String::new();

        loop {
            match self.peek_char() {
                Some('"') => {
                    self.advance_char();
                    return Ok(out);
                }
                Some('\\') => {
                    self.advance_char();
                    out.push(self.parse_escape()?);
                }
                Some(ch) if ch <= '\u{1F}' => {
                    return Err(self.error("control characters must be escaped"));
                }
                Some(_) => {
                    let ch = self.advance_char().expect("peeked char exists");
                    out.push(ch);
                }
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, JsonError> {
        match self.advance_char() {
            Some('"') => Ok('"'),
            Some('\\') => Ok('\\'),
            Some('/') => Ok('/'),
            Some('b') => Ok('\u{0008}'),
            Some('f') => Ok('\u{000C}'),
            Some('n') => Ok('\n'),
            Some('r') => Ok('\r'),
            Some('t') => Ok('\t'),
            Some('u') => self.parse_unicode_escape(),
            Some(_) => Err(self.error("invalid escape sequence")),
            None => Err(self.error("unterminated escape sequence")),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let high = self.parse_hex_u16()?;
        if !(0xD800..=0xDFFF).contains(&high) {
            return char::from_u32(u32::from(high))
                .ok_or_else(|| self.error("invalid unicode escape"));
        }

        if !(0xD800..=0xDBFF).contains(&high) {
            return Err(self.error("unexpected low surrogate"));
        }

        if self.advance_char() != Some('\\') || self.advance_char() != Some('u') {
            return Err(self.error("missing low surrogate after high surrogate"));
        }

        let low = self.parse_hex_u16()?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(self.error("invalid low surrogate"));
        }

        let high_ten = u32::from(high) - 0xD800;
        let low_ten = u32::from(low) - 0xDC00;
        let scalar = 0x10000 + ((high_ten << 10) | low_ten);
        char::from_u32(scalar).ok_or_else(|| self.error("invalid surrogate pair"))
    }

    fn parse_hex_u16(&mut self) -> Result<u16, JsonError> {
        let mut value = 0u16;
        for _ in 0..4 {
            let ch = self
                .advance_char()
                .ok_or_else(|| self.error("unexpected end of input in unicode escape"))?;
            let digit = ch
                .to_digit(16)
                .ok_or_else(|| self.error("invalid hex digit in unicode escape"))?;
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect_char('[')?;
        self.skip_whitespace();

        let mut items = Vec::new();
        if self.peek_char() == Some(']') {
            self.advance_char();
            return Ok(JsonValue::Array(items));
        }

        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek_char() {
                Some(',') => {
                    self.advance_char();
                    self.skip_whitespace();
                }
                Some(']') => {
                    self.advance_char();
                    return Ok(JsonValue::Array(items));
                }
                Some(_) => return Err(self.error("expected ',' or ']' in array")),
                None => return Err(self.error("unterminated array")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect_char('{')?;
        self.skip_whitespace();

        let mut entries = BTreeMap::new();
        if self.peek_char() == Some('}') {
            self.advance_char();
            return Ok(JsonValue::Object(entries));
        }

        loop {
            self.skip_whitespace();
            let key = match self.peek_char() {
                Some('"') => self.parse_string()?,
                Some(_) => return Err(self.error("object keys must be strings")),
                None => return Err(self.error("unterminated object")),
            };

            self.skip_whitespace();
            self.expect_char(':')?;
            self.skip_whitespace();

            let value = self.parse_value()?;
            entries.insert(key, value);

            self.skip_whitespace();
            match self.peek_char() {
                Some(',') => {
                    self.advance_char();
                    self.skip_whitespace();
                }
                Some('}') => {
                    self.advance_char();
                    return Ok(JsonValue::Object(entries));
                }
                Some(_) => return Err(self.error("expected ',' or '}' in object")),
                None => return Err(self.error("unterminated object")),
            }
        }
    }

    fn consume_literal(&mut self, expected: &str) -> Result<(), JsonError> {
        if self.try_consume_literal(expected) {
            Ok(())
        } else {
            Err(self.error(format!("expected '{expected}'")))
        }
    }

    fn try_consume_literal(&mut self, expected: &str) -> bool {
        let checkpoint = (self.index, self.line, self.column);
        for ch in expected.chars() {
            if self.advance_char() != Some(ch) {
                self.index = checkpoint.0;
                self.line = checkpoint.1;
                self.column = checkpoint.2;
                return false;
            }
        }
        true
    }

    fn expect_char(&mut self, expected: char) -> Result<(), JsonError> {
        match self.advance_char() {
            Some(ch) if ch == expected => Ok(()),
            Some(_) => Err(self.error(format!("expected '{expected}'"))),
            None => Err(self.error(format!("expected '{expected}', found end of input"))),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_char(), Some(' ' | '\n' | '\r' | '\t')) {
            self.advance_char();
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.index..].chars().next()
    }

    fn advance_char(&mut self) -> Option<char> {
        let ch = self.peek_char()?;
        self.index += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(ch)
    }

    fn is_eof(&self) -> bool {
        self.index >= self.input.len()
    }

    fn error(&self, message: impl Into<String>) -> JsonError {
        JsonError::new(message, self.line, self.column)
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_json() {
        let value = parse_json(
            r#"{
                "name": "parser",
                "active": true,
                "count": 3,
                "items": [null, false, {"pi": 3.14}],
                "unicode": "\uD83D\uDE80"
            }"#,
        )
        .unwrap();

        let JsonValue::Object(root) = value else {
            panic!("expected object");
        };

        assert_eq!(root.get("name"), Some(&JsonValue::String("parser".into())));
        assert_eq!(root.get("active"), Some(&JsonValue::Bool(true)));
        assert_eq!(root.get("count"), Some(&JsonValue::Number(3.0)));
        assert_eq!(root.get("unicode"), Some(&JsonValue::String("🚀".into())));
    }

    #[test]
    fn rejects_trailing_characters() {
        let err = parse_json("true false").unwrap_err();
        assert_eq!(err.message, "trailing characters");
    }

    #[test]
    fn rejects_leading_zero() {
        let err = parse_json("01").unwrap_err();
        assert_eq!(err.message, "leading zeros are not allowed");
    }

    #[test]
    fn rejects_unescaped_control_character() {
        let err = parse_json("\"\u{0007}\"").unwrap_err();
        assert_eq!(err.message, "control characters must be escaped");
    }

    #[test]
    fn tracks_line_and_column() {
        let err = parse_json("{\n  \"a\": [1,\n}").unwrap_err();
        assert_eq!(err.line, 3);
        assert_eq!(err.column, 1);
    }

    #[test]
    fn handles_number_forms() {
        assert_eq!(parse_json("0").unwrap(), JsonValue::Number(0.0));
        assert_eq!(parse_json("-12.5").unwrap(), JsonValue::Number(-12.5));
        assert_eq!(parse_json("6.022e23").unwrap(), JsonValue::Number(6.022e23));
    }
}

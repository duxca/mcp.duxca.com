//! 元実装（Node）の緩い型変換を再現する小道具。

use serde_json::Value;

/// JS の `\s` / `String.prototype.trim` が空白とみなす文字。
pub fn is_js_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c.is_whitespace() && c != '\u{85}')
}

pub fn trim(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// JS の `.length`（UTF-16 コードユニット数）。
pub fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JS の `Number(v)`。配列・オブジェクトは NaN 扱い。
pub fn number(v: &Value) -> f64 {
    match v {
        Value::Null => 0.0,
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) => string_to_number(trim(s)),
        Value::Array(_) | Value::Object(_) => f64::NAN,
    }
}

fn string_to_number(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    match s {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = s.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix)
                .map(|n| n as f64)
                .unwrap_or(f64::NAN);
        }
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E'))
    {
        return f64::NAN;
    }
    s.parse().unwrap_or(f64::NAN)
}

/// JS で truthy な値を `String(v)` にする（falsy なら None）。
pub fn truthy_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) if n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()) => {
            Some(n.to_string())
        }
        Value::Bool(true) => Some("true".into()),
        _ => None,
    }
}

pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod js_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn number_follows_js() {
        assert_eq!(number(&json!(null)), 0.0);
        assert_eq!(number(&json!(" 12 ")), 12.0);
        assert_eq!(number(&json!("")), 0.0);
        assert_eq!(number(&json!("1e3")), 1000.0);
        assert_eq!(number(&json!("0x10")), 16.0);
        assert_eq!(number(&json!(true)), 1.0);
        assert!(number(&json!("abc")).is_nan());
        assert!(number(&json!("inf")).is_nan());
        assert!(number(&json!({})).is_nan());
        assert_eq!(number(&json!("Infinity")), f64::INFINITY);
    }

    #[test]
    fn utf16_length_counts_surrogate_pairs() {
        assert_eq!(utf16_len("abc"), 3);
        assert_eq!(utf16_len("😀"), 2);
        assert_eq!(utf16_len("あ"), 1);
        assert_eq!(trim("\u{feff} a \u{3000}"), "a");
    }
}

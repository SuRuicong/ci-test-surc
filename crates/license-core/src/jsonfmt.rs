//! JS `JSON.stringify` 字节级兼容序列化。
//!
//! 背景：签名输入与落盘文件都要求与 Node 版逐字节一致。serde_json 默认序列化
//! 在两点上与 JSON.stringify 不同：
//! 1. 浮点 30.0 会输出 "30.0"，而 JS 输出 "30"（Number 最短往返表示）；
//! 2. 这里的实现显式控制键序（canonical 排序 / 保留文档序），不依赖 Map 实现细节。
//!
//! 字符串转义与 JSON.stringify 一致：非 ASCII 原样保留（UTF-8），
//! 控制字符用 \b \f \n \r \t 或 \u00xx（小写 hex）。

use serde_json::{Map, Value};

/// JS Number → 最短十进制表示（近似 ECMAScript Number::toString）。
pub fn number_to_js(n: &serde_json::Number) -> String {
    if let Some(u) = n.as_u64() {
        return u.to_string();
    }
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    let f = n.as_f64().unwrap_or(f64::NAN);
    if !f.is_finite() {
        // canonical-json 规则会提前拒绝非有限数；这里兜底按 null 处理不到达。
        return "null".to_string();
    }
    // JS：整数范围内（|n| < 2^53）的整数值不带小数点。
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        return format!("{}", f as i64);
    }
    let mut buf = ryu::Buffer::new();
    let s = buf.format_finite(f);
    jsify_exponent(s)
}

/// ryu 输出 "1e21"/"1e-7"，JS 输出 "1e+21"/"1e-7"（正指数带显式符号）。
fn jsify_exponent(s: &str) -> String {
    match s.find(['e', 'E']) {
        None => s.to_string(),
        Some(i) => {
            let (mantissa, exp) = s.split_at(i);
            let exp = &exp[1..];
            if exp.starts_with('-') {
                format!("{mantissa}e{exp}")
            } else {
                format!("{mantissa}e+{exp}")
            }
        }
    }
}

/// JSON.stringify 的字符串转义（输出含两侧引号）。
pub fn escape_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// canonical JSON：对象键按字典序排序、无缩进无空白（对应 canonical-json.ts）。
/// preserve_order 下 Map 是 IndexMap，排序用 BTree 视图，结果与 Object.keys().sort() 一致
/// （键为合法 UTF-8 字符串，JS 按 UTF-16 码元排序；对 BMP 字符二者一致）。
pub fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_to_js(n)),
        Value::String(s) => out.push_str(&escape_js_string(s)),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, &Value> =
                map.iter().collect::<std::collections::BTreeMap<_, _>>();
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&escape_js_string(k));
                out.push(':');
                write_canonical(val, out);
            }
            out.push('}');
        }
    }
}

pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

/// JSON.stringify(v)：无空白、键保留插入序（checker stdout 契约与账本 JSONL 用）。
pub fn write_compact(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_to_js(n)),
        Value::String(s) => out.push_str(&escape_js_string(s)),
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&escape_js_string(k));
                out.push(':');
                write_compact(val, out);
            }
            out.push('}');
        }
    }
}

pub fn compact_json(v: &Value) -> String {
    let mut out = String::new();
    write_compact(v, &mut out);
    out
}

/// JSON.stringify(v, null, 2)：2 空格缩进、键保留插入序（preserve_order 即文档序）。
pub fn write_pretty(v: &Value, indent: usize, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number_to_js(n)),
        Value::String(s) => out.push_str(&escape_js_string(s)),
        Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            let child = indent + 2;
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                out.push_str(&" ".repeat(child));
                write_pretty(item, child, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            let child = indent + 2;
            let entries: Vec<(&String, &Value)> = map.iter().collect();
            for (i, (k, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                out.push_str(&" ".repeat(child));
                out.push_str(&escape_js_string(k));
                out.push_str(": ");
                write_pretty(val, child, out);
            }
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            out.push('}');
        }
    }
}

pub fn pretty_json(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(v, 0, &mut out);
    out
}

/// 按给定键序构造对象（preserve_order 下即序列化顺序）。
pub fn object_in_order(entries: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (k, v) in entries {
        map.insert(k.to_string(), v);
    }
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_keys_and_compacts() {
        let v = json!({"b": 1, "a": {"y": [true, null], "x": "s"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"x":"s","y":[true,null]},"b":1}"#);
    }

    #[test]
    fn numbers_match_js_stringify() {
        assert_eq!(number_to_js(&serde_json::Number::from(30)), "30");
        let f: Value = serde_json::from_str("30.0").unwrap();
        assert_eq!(canonical_json(&f), "30");
        let f: Value = serde_json::from_str("1.5").unwrap();
        assert_eq!(canonical_json(&f), "1.5");
        let f: Value = serde_json::from_str("31622400").unwrap();
        assert_eq!(canonical_json(&f), "31622400");
    }

    #[test]
    fn pretty_matches_json_stringify_2() {
        let v = json!({"licenseId": "lic-2026-0001", "baseCumulativeSeconds": 0});
        assert_eq!(
            pretty_json(&v),
            "{\n  \"licenseId\": \"lic-2026-0001\",\n  \"baseCumulativeSeconds\": 0\n}"
        );
    }

    #[test]
    fn escape_keeps_non_ascii() {
        assert_eq!(escape_js_string("某市公安局"), "\"某市公安局\"");
        assert_eq!(escape_js_string("a\nb\t\"q\""), "\"a\\nb\\t\\\"q\\\"\"");
    }
}

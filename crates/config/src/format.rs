//! JSON、JSONC（Extended JSON）与带锚点（`&`/`*`/`<<:`）YAML 配置解析。

use kerlico_core::{Error, Result};
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

pub fn parse_config_value(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Config("配置文件必须为有效 UTF-8 文本".into()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    if let Ok(val) = serde_json::from_str::<Value>(text) {
        return Ok(val);
    }

    let cleaned = strip_jsonc_and_trailing_commas(text)?;
    let trimmed = cleaned.trim_start();
    if trimmed.starts_with('{')
        && let Ok(val) = serde_json::from_str::<Value>(&cleaned)
    {
        return Ok(val);
    }

    if !trimmed.starts_with('{') {
        let mut val = parse_yaml_with_anchors(text)?;
        normalize_yaml_root(&mut val);
        return Ok(val);
    }

    Err(Error::Config("JSON/JSONC/YAML 结构或字段不合法".into()))
}

pub fn strip_jsonc_and_trailing_commas(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut no_comments = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            no_comments.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                i += 1;
                no_comments.push(bytes[i] as char);
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            no_comments.push('"');
            i += 1;
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'#' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            let mut closed = false;
            while i + 1 < bytes.len() {
                if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                    i += 2;
                    closed = true;
                    break;
                }
                if bytes[i] == b'\n' {
                    no_comments.push('\n');
                }
                i += 1;
            }
            if !closed {
                return Err(Error::Config("JSONC 块注释未闭合".into()));
            }
        } else {
            let ch = input[i..].chars().next().unwrap();
            no_comments.push(ch);
            i += ch.len_utf8();
        }
    }

    // Strip trailing commas before '}' or ']' outside strings
    let nc_bytes = no_comments.as_bytes();
    let mut out = String::with_capacity(no_comments.len());
    let mut j = 0;
    let mut in_str = false;
    while j < nc_bytes.len() {
        let b = nc_bytes[j];
        if in_str {
            out.push(b as char);
            if b == b'\\' && j + 1 < nc_bytes.len() {
                j += 1;
                out.push(nc_bytes[j] as char);
            } else if b == b'"' {
                in_str = false;
            }
            j += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            out.push('"');
            j += 1;
        } else if b == b',' {
            let mut k = j + 1;
            while k < nc_bytes.len() && nc_bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < nc_bytes.len() && (nc_bytes[k] == b'}' || nc_bytes[k] == b']') {
                j += 1;
            } else {
                out.push(',');
                j += 1;
            }
        } else {
            let ch = no_comments[j..].chars().next().unwrap();
            out.push(ch);
            j += ch.len_utf8();
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
struct YamlLine {
    indent: usize,
    text: String,
}

pub fn parse_yaml_with_anchors(input: &str) -> Result<Value> {
    let mut lines = Vec::new();
    for raw_line in input.lines() {
        let stripped = strip_yaml_comment(raw_line);
        let trimmed_end = stripped.trim_end();
        let trimmed = trimmed_end.trim_start();
        if trimmed.is_empty() || trimmed == "---" || trimmed == "..." {
            continue;
        }
        let indent = trimmed_end.len() - trimmed.len();
        lines.push(YamlLine {
            indent,
            text: trimmed.to_owned(),
        });
    }
    if lines.is_empty() {
        return Err(Error::Config("YAML 内容为空".into()));
    }
    let mut anchors = HashMap::new();
    let mut idx = 0;
    let base_indent = lines[0].indent;
    parse_yaml_block(&lines, &mut idx, base_indent, &mut anchors)
}

fn strip_yaml_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_space = true;
    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' && chars.peek() == Some(&'\'') {
                out.push('\'');
                out.push(chars.next().unwrap());
                continue;
            } else if c == '\'' {
                in_single = false;
            }
            out.push(c);
            prev_space = false;
        } else if in_double {
            out.push(c);
            if c == '\\'
                && let Some(next) = chars.next()
            {
                out.push(next);
            } else if c == '"' {
                in_double = false;
            }
            prev_space = false;
        } else if c == '\'' {
            in_single = true;
            out.push(c);
            prev_space = false;
        } else if c == '"' {
            in_double = true;
            out.push(c);
            prev_space = false;
        } else if c == '#' && prev_space {
            break;
        } else {
            prev_space = c.is_whitespace();
            out.push(c);
        }
    }
    out
}

fn parse_yaml_block(
    lines: &[YamlLine],
    idx: &mut usize,
    min_indent: usize,
    anchors: &mut HashMap<String, Value>,
) -> Result<Value> {
    if *idx >= lines.len() {
        return Ok(Value::Null);
    }
    let first = &lines[*idx];
    if first.text.starts_with("- ") || first.text == "-" {
        parse_yaml_seq(lines, idx, first.indent, anchors)
    } else {
        parse_yaml_map(lines, idx, min_indent, anchors)
    }
}

fn parse_yaml_seq(
    lines: &[YamlLine],
    idx: &mut usize,
    seq_indent: usize,
    anchors: &mut HashMap<String, Value>,
) -> Result<Value> {
    let mut arr = Vec::new();
    while *idx < lines.len() {
        let line = &lines[*idx];
        if line.indent < seq_indent {
            break;
        }
        if line.indent > seq_indent || !(line.text.starts_with("- ") || line.text == "-") {
            break;
        }
        let rest = line.text.strip_prefix("- ").unwrap_or("").trim();
        let item_indent = line.indent + 2;
        *idx += 1;

        let (anchor_name, rest) = extract_leading_anchor(rest);
        let val = if rest.is_empty() {
            if *idx < lines.len() && lines[*idx].indent > seq_indent {
                let child_indent = lines[*idx].indent;
                parse_yaml_block(lines, idx, child_indent, anchors)?
            } else {
                Value::Null
            }
        } else if is_yaml_key_value(rest) && !rest.starts_with('{') && !rest.starts_with('[') {
            let (k, v_rest) = split_yaml_key_value(rest)?;
            let mut map = Map::new();
            let first_val = parse_yaml_rhs(v_rest, lines, idx, item_indent, anchors)?;
            apply_yaml_key(&mut map, &k, first_val)?;
            if *idx < lines.len() && lines[*idx].indent >= item_indent {
                let sub_indent = lines[*idx].indent;
                if let Value::Object(extra) = parse_yaml_map(lines, idx, sub_indent, anchors)? {
                    for (ek, ev) in extra {
                        map.entry(ek).or_insert(ev);
                    }
                }
            }
            Value::Object(map)
        } else {
            parse_yaml_scalar_or_flow(rest, anchors)?
        };

        if let Some(name) = anchor_name {
            anchors.insert(name, val.clone());
        }
        arr.push(val);
    }
    Ok(Value::Array(arr))
}

fn parse_yaml_map(
    lines: &[YamlLine],
    idx: &mut usize,
    map_indent: usize,
    anchors: &mut HashMap<String, Value>,
) -> Result<Value> {
    let mut map = Map::new();
    let mut merged = Map::new();
    while *idx < lines.len() {
        let line = &lines[*idx];
        if line.indent < map_indent {
            break;
        }
        if line.text.starts_with("- ") || line.text == "-" {
            break;
        }
        let current_indent = line.indent;
        let (key, rhs) = split_yaml_key_value(&line.text)?;
        *idx += 1;
        let val = parse_yaml_rhs(rhs, lines, idx, current_indent + 1, anchors)?;
        if key == "<<" {
            match val {
                Value::Object(obj) => {
                    for (mk, mv) in obj {
                        merged.entry(mk).or_insert(mv);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        if let Value::Object(obj) = item {
                            for (mk, mv) in obj {
                                merged.entry(mk).or_insert(mv);
                            }
                        }
                    }
                }
                _ => return Err(Error::Config("YAML <<: 合并目标必须为映射对象".into())),
            }
        } else {
            apply_yaml_key(&mut map, &key, val)?;
        }
    }
    for (mk, mv) in merged {
        map.entry(mk).or_insert(mv);
    }
    Ok(Value::Object(map))
}

fn apply_yaml_key(map: &mut Map<String, Value>, key: &str, val: Value) -> Result<()> {
    map.insert(unquote_yaml_str(key), val);
    Ok(())
}

fn parse_yaml_rhs(
    rhs: &str,
    lines: &[YamlLine],
    idx: &mut usize,
    min_child_indent: usize,
    anchors: &mut HashMap<String, Value>,
) -> Result<Value> {
    let (anchor_name, rest) = extract_leading_anchor(rhs.trim());
    let val = if rest.is_empty() {
        if *idx < lines.len() && lines[*idx].indent >= min_child_indent {
            let child_indent = lines[*idx].indent;
            parse_yaml_block(lines, idx, child_indent, anchors)?
        } else if *idx < lines.len()
            && lines[*idx].indent + 1 == min_child_indent
            && (lines[*idx].text.starts_with("- ") || lines[*idx].text == "-")
        {
            let child_indent = lines[*idx].indent;
            parse_yaml_seq(lines, idx, child_indent, anchors)?
        } else {
            Value::Null
        }
    } else {
        parse_yaml_scalar_or_flow(rest, anchors)?
    };
    if let Some(name) = anchor_name {
        anchors.insert(name, val.clone());
    }
    Ok(val)
}

fn extract_leading_anchor(s: &str) -> (Option<String>, &str) {
    let trimmed = s.trim_start();
    if let Some(after_amp) = trimmed.strip_prefix('&') {
        let end = after_amp
            .find(|c: char| c.is_whitespace())
            .unwrap_or(after_amp.len());
        let name = &after_amp[..end];
        if !name.is_empty() {
            return (Some(name.to_owned()), after_amp[end..].trim_start());
        }
    }
    (None, trimmed)
}

fn is_yaml_key_value(s: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single
                && !in_double
                && (i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace()) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn split_yaml_key_value(s: &str) -> Result<(String, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single
                && !in_double
                && (i + 1 == bytes.len() || bytes[i + 1].is_ascii_whitespace()) =>
            {
                let key = s[..i].trim().to_owned();
                let rhs = s[i + 1..].trim();
                return Ok((key, rhs));
            }
            _ => {}
        }
    }
    Err(Error::Config("YAML 键值行缺少冒号分隔符".into()))
}

fn parse_yaml_scalar_or_flow(s: &str, anchors: &mut HashMap<String, Value>) -> Result<Value> {
    let trimmed = s.trim();
    if let Some(alias) = trimmed.strip_prefix('*') {
        return anchors
            .get(alias.trim())
            .cloned()
            .ok_or_else(|| Error::Config(format!("YAML 锚点引用 *{alias} 未定义")));
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let parts = split_flow_items(inner);
        let mut arr = Vec::with_capacity(parts.len());
        for p in parts {
            arr.push(parse_yaml_scalar_or_flow(p, anchors)?);
        }
        return Ok(Value::Array(arr));
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let parts = split_flow_items(inner);
        let mut map = Map::new();
        let mut merged = Map::new();
        for p in parts {
            let (k, v_str) = split_yaml_key_value(p)?;
            let (anchor, v_clean) = extract_leading_anchor(v_str);
            let val = parse_yaml_scalar_or_flow(v_clean, anchors)?;
            if let Some(a) = anchor {
                anchors.insert(a, val.clone());
            }
            if k == "<<" {
                if let Value::Object(obj) = val {
                    for (mk, mv) in obj {
                        merged.entry(mk).or_insert(mv);
                    }
                }
            } else {
                map.insert(unquote_yaml_str(&k), val);
            }
        }
        for (mk, mv) in merged {
            map.entry(mk).or_insert(mv);
        }
        return Ok(Value::Object(map));
    }
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        return Ok(Value::String(unquote_yaml_str(trimmed)));
    }
    match trimmed {
        "null" | "Null" | "NULL" | "~" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if let Ok(u) = trimmed.parse::<u64>() {
        return Ok(Value::Number(Number::from(u)));
    }
    if let Ok(i) = trimmed.parse::<i64>() {
        return Ok(Value::Number(Number::from(i)));
    }
    if let Ok(f) = trimmed.parse::<f64>()
        && let Some(n) = Number::from_f64(f)
    {
        return Ok(Value::Number(n));
    }
    Ok(Value::String(trimmed.to_owned()))
}

fn split_flow_items(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'[' | b'{' if !in_single && !in_double => depth += 1,
            b']' | b'}' if !in_single && !in_double => depth = depth.saturating_sub(1),
            b',' if !in_single && !in_double && depth == 0 => {
                let piece = s[start..i].trim();
                if !piece.is_empty() {
                    out.push(piece);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

fn unquote_yaml_str(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        serde_json::from_str::<String>(t).unwrap_or_else(|_| t[1..t.len() - 1].to_owned())
    } else if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
        t[1..t.len() - 1].replace("''", "'")
    } else {
        t.to_owned()
    }
}

fn normalize_yaml_root(root: &mut Value) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    if !obj.contains_key("version") {
        obj.insert("version".into(), Value::Number(Number::from(2u64)));
    }
    if !obj.contains_key("outbounds")
        && let Some(Value::Array(proxies)) = obj.remove("proxies")
    {
        let mut outbounds = Vec::with_capacity(proxies.len());
        for mut p in proxies {
            if let Some(m) = p.as_object_mut() {
                if !m.contains_key("tag")
                    && let Some(name) = m.remove("name")
                {
                    m.insert("tag".into(), name);
                }
                let tag = m
                    .remove("tag")
                    .unwrap_or_else(|| Value::String("proxy".into()));
                let kind = m
                    .remove("type")
                    .or_else(|| m.remove("protocol"))
                    .unwrap_or_else(|| Value::String("direct".into()));
                let options = if let Some(opts) = m.remove("options") {
                    opts
                } else {
                    Value::Object(m.clone())
                };
                let mut spec = Map::new();
                spec.insert("tag".into(), tag);
                spec.insert("type".into(), kind);
                spec.insert("options".into(), options);
                outbounds.push(Value::Object(spec));
            }
        }
        obj.insert("outbounds".into(), Value::Array(outbounds));
    }
    if !obj.contains_key("outbounds") {
        let mut direct = Map::new();
        direct.insert("tag".into(), Value::String("direct".into()));
        direct.insert("type".into(), Value::String("direct".into()));
        obj.insert(
            "outbounds".into(),
            Value::Array(vec![Value::Object(direct)]),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jsonc_with_comments_and_trailing_commas() {
        let raw = r#"{
            // line comment
            "version": 2, # hash comment
            /* multi-line
               block comment */
            "outbounds": [
                {
                    "tag": "direct",
                    "type": "direct",
                },
            ],
        }"#;
        let val = parse_config_value(raw.as_bytes()).expect("parse jsonc");
        assert_eq!(val["version"], 2);
        assert_eq!(val["outbounds"][0]["tag"], "direct");
    }

    #[test]
    fn parses_yaml_with_anchors_and_merge_keys() {
        let raw = r#"
# YAML config with anchors
version: 2
common_hc: &hc
  enable: true
  url: "https://cp.cloudflare.com/generate_204"
  interval: 300

proxy-providers:
  sub_a:
    type: http
    url: "https://example.com/sub"
    health-check:
      <<: *hc
      timeout: 5000

outbounds:
  - tag: direct
    type: direct
"#;
        let val = parse_config_value(raw.as_bytes()).expect("parse yaml");
        assert_eq!(val["version"], 2);
        assert_eq!(
            val["proxy-providers"]["sub_a"]["health-check"]["url"],
            "https://cp.cloudflare.com/generate_204"
        );
        assert_eq!(
            val["proxy-providers"]["sub_a"]["health-check"]["timeout"],
            5000
        );
        // Remove helper anchor key before full config deserialization if needed, or verify it parsed
        assert_eq!(val["common_hc"]["interval"], 300);
    }
}

//! JSON、JSONC（Extended JSON）与带锚点（`&`/`*`/`<<:`）YAML 配置解析。

use kerlico_core::{Error, Result};
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

pub fn parse_config_value(bytes: &[u8]) -> Result<Value> {
    parse_config_value_with_format(bytes, None)
}

pub fn parse_config_value_with_format(bytes: &[u8], format: Option<&str>) -> Result<Value> {
    if bytes.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    let fmt = format.unwrap_or("").trim().to_ascii_lowercase();
    if fmt == "protobuf" || fmt == "pb" || bytes.starts_with(b"KPB\x01") {
        let mut val = parse_protobuf_config(bytes)?;
        normalize_config_value(&mut val)?;
        return Ok(val);
    }

    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Config("配置文件必须为有效 UTF-8 文本".into()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    if fmt == "toml" {
        let mut val = parse_toml_config(text)?;
        normalize_yaml_root(&mut val)?;
        normalize_config_value(&mut val)?;
        return Ok(val);
    }

    if let Ok(mut val) = serde_json::from_str::<Value>(text) {
        normalize_config_value(&mut val)?;
        return Ok(val);
    }

    let cleaned = strip_jsonc_and_trailing_commas(text)?;
    let trimmed = cleaned.trim_start();
    if trimmed.starts_with('{')
        && let Ok(mut val) = serde_json::from_str::<Value>(&cleaned)
    {
        normalize_config_value(&mut val)?;
        return Ok(val);
    }

    if !trimmed.starts_with('{') {
        if looks_like_toml(text)
            && let Ok(mut val) = parse_toml_config(text)
        {
            normalize_yaml_root(&mut val)?;
            normalize_config_value(&mut val)?;
            return Ok(val);
        }
        let mut val = parse_yaml_with_anchors(text)?;
        normalize_yaml_root(&mut val)?;
        normalize_config_value(&mut val)?;
        return Ok(val);
    }

    Err(Error::Config(
        "JSON/JSONC/YAML/TOML 结构或字段不合法".into(),
    ))
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
    // 带前导零的数字串（如 Reality `short-id: 0123`）按字符串保留，避免丢失前导零。
    if trimmed.len() > 1 && trimmed.starts_with('0') && trimmed.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(Value::String(trimmed.to_owned()));
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

fn normalize_yaml_root(root: &mut Value) -> Result<()> {
    let Some(obj) = root.as_object_mut() else {
        return Ok(());
    };
    if !obj.contains_key("version") {
        obj.insert("version".into(), Value::Number(Number::from(2u64)));
    }
    if !obj.contains_key("outbounds")
        && let Some(Value::Array(proxies)) = obj.remove("proxies")
    {
        let mut outbounds = Vec::with_capacity(proxies.len());
        for proxy in proxies {
            let (tag, kind, options) = crate::mihomo::member_outbound(proxy)?;
            let mut spec = Map::new();
            spec.insert("tag".into(), Value::String(tag));
            spec.insert("type".into(), Value::String(kind));
            spec.insert("options".into(), options);
            outbounds.push(Value::Object(spec));
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
    Ok(())
}

fn looks_like_toml(input: &str) -> bool {
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if (line.starts_with('[') && line.ends_with(']')) || line.contains(" = ") {
            return true;
        }
        break;
    }
    false
}

pub fn parse_toml_config(input: &str) -> Result<Value> {
    let mut root = Map::new();
    let mut current_path: Vec<String> = Vec::new();
    let mut is_array_table = false;

    for raw in input.lines() {
        let line = strip_yaml_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(inner) = trimmed
            .strip_prefix("[[")
            .and_then(|s| s.strip_suffix("]]"))
        {
            current_path = inner
                .split('.')
                .map(|s| unquote_yaml_str(s.trim()))
                .collect();
            is_array_table = true;
            ensure_toml_array_entry(&mut root, &current_path)?;
            continue;
        }
        if let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_path = inner
                .split('.')
                .map(|s| unquote_yaml_str(s.trim()))
                .collect();
            is_array_table = false;
            continue;
        }
        let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
            return Err(Error::Config("TOML 键值行缺少 '='".into()));
        };
        let key = unquote_yaml_str(k_raw.trim());
        let mut dummy_anchors = HashMap::new();
        let val = parse_yaml_scalar_or_flow(v_raw.trim(), &mut dummy_anchors)?;
        let target_map = get_toml_target_map(&mut root, &current_path, is_array_table)?;
        target_map.insert(key, val);
    }
    Ok(Value::Object(root))
}

fn ensure_toml_array_entry(root: &mut Map<String, Value>, path: &[String]) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Config("TOML [[table]] 名称不能为空".into()));
    }
    let mut cur = root;
    for seg in &path[..path.len() - 1] {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        cur = entry
            .as_object_mut()
            .ok_or_else(|| Error::Config("TOML 路径冲突".into()))?;
    }
    let last = &path[path.len() - 1];
    let arr_val = cur
        .entry(last.clone())
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = arr_val
        .as_array_mut()
        .ok_or_else(|| Error::Config("TOML 表数组类型冲突".into()))?;
    arr.push(Value::Object(Map::new()));
    Ok(())
}

fn get_toml_target_map<'a>(
    root: &'a mut Map<String, Value>,
    path: &[String],
    is_array_table: bool,
) -> Result<&'a mut Map<String, Value>> {
    if path.is_empty() {
        return Ok(root);
    }
    let mut cur = root;
    for seg in &path[..path.len() - 1] {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        cur = entry
            .as_object_mut()
            .ok_or_else(|| Error::Config("TOML 表路径冲突".into()))?;
    }
    let last = &path[path.len() - 1];
    if is_array_table {
        let arr = cur
            .get_mut(last)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Error::Config("TOML 数组表不存在".into()))?;
        arr.last_mut()
            .and_then(Value::as_object_mut)
            .ok_or_else(|| Error::Config("TOML 数组表元素非对象".into()))
    } else {
        let entry = cur
            .entry(last.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        entry
            .as_object_mut()
            .ok_or_else(|| Error::Config("TOML 表路径非对象".into()))
    }
}

pub fn parse_protobuf_config(bytes: &[u8]) -> Result<Value> {
    let payload = if let Some(rest) = bytes.strip_prefix(b"KPB\x01") {
        rest
    } else if bytes.len() >= 2 && bytes[0] == 0x0a {
        // Length-delimited field 1 containing JSON/UTF-8 config payload
        let mut idx = 1usize;
        let mut len = 0usize;
        let mut shift = 0u32;
        while idx < bytes.len() {
            let b = bytes[idx];
            idx += 1;
            len |= ((b & 0x7f) as usize) << shift;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
        }
        if idx + len <= bytes.len() {
            &bytes[idx..idx + len]
        } else {
            bytes
        }
    } else {
        bytes
    };
    serde_json::from_slice::<Value>(payload)
        .map_err(|_| Error::Config("Protobuf 配置文件解码失败".into()))
}

pub fn check_version_constraint(version_val: &Value) -> Result<()> {
    let current = (1u32, 8u32, 0u32);
    match version_val {
        Value::Number(n) => {
            if n.as_u64() != Some(2) {
                return Err(Error::Config(
                    "仅支持配置版本 2；迁移说明见 docs/config-v2-migration.md".into(),
                ));
            }
        }
        Value::String(s) => {
            let ver = parse_semver(s)?;
            if current < ver {
                return Err(Error::Config("当前内核版本低于配置要求的最低版本".into()));
            }
        }
        Value::Object(map) => {
            if let Some(min_s) = map.get("min").and_then(Value::as_str) {
                let min_v = parse_semver(min_s)?;
                if current < min_v {
                    return Err(Error::Config("当前内核版本低于 version.min".into()));
                }
            }
            if let Some(max_s) = map.get("max").and_then(Value::as_str) {
                let max_v = parse_semver(max_s)?;
                if current > max_v {
                    return Err(Error::Config("当前内核版本高于 version.max".into()));
                }
            }
        }
        _ => {
            return Err(Error::Config("version 字段类型不合法".into()));
        }
    }
    Ok(())
}

fn parse_semver(s: &str) -> Result<(u32, u32, u32)> {
    let clean = s.trim().trim_start_matches('v');
    let mut parts = clean.split('.');
    let major: u32 = parts
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| Error::Config("版本号格式须为 x.y.z".into()))?;
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Ok((major, minor, patch))
}

pub fn normalize_config_value(root: &mut Value) -> Result<()> {
    let Some(obj) = root.as_object_mut() else {
        return Ok(());
    };
    if let Some(ver) = obj.get("version").cloned() {
        check_version_constraint(&ver)?;
        if !ver.is_number() {
            obj.insert("version".into(), Value::Number(Number::from(2u64)));
        }
    } else {
        obj.insert("version".into(), Value::Number(Number::from(2u64)));
    }

    // Array shorthand: wrap single non-array value into 1-element array for array fields
    for key in [
        "accounts",
        "outbounds",
        "inbounds",
        "nodes",
        "local_inbounds",
        "lan_allowed_ips",
        "lan-allowed-ips",
        "lan_disallowed_ips",
        "lan-disallowed-ips",
        "certificate_providers",
        "certificate-providers",
        "routes",
        "rule_set",
        "rule-set",
        "proxy_groups",
        "proxy-groups",
        "services",
        "http_clients",
        "http-clients",
        "network_namespaces",
        "network-namespaces",
    ] {
        if let Some(val) = obj.get_mut(key)
            && !val.is_array()
            && !val.is_null()
        {
            let single = val.take();
            *val = Value::Array(vec![single]);
        }
    }

    // Normalize top-level Clash/Mihomo controller fields into `control`
    let ext_ctrl = obj
        .remove("external-controller")
        .or_else(|| obj.remove("external_controller"));
    let secret = obj.remove("secret");
    let ext_ui = obj
        .remove("external-ui")
        .or_else(|| obj.remove("external_ui"));
    let ext_ui_name = obj
        .remove("external-ui-name")
        .or_else(|| obj.remove("external_ui_name"));
    let ext_ui_url = obj
        .remove("external-ui-url")
        .or_else(|| obj.remove("external_ui_url"));
    let cors_origins = obj
        .remove("external-controller-cors-allow-origins")
        .or_else(|| obj.remove("cors-allow-origins"));
    let cors_pna = obj
        .remove("external-controller-cors-allow-private-network")
        .or_else(|| obj.remove("cors-allow-private-network"));
    let ext_tls = obj.remove("external-controller-tls");
    let ext_unix = obj.remove("external-controller-unix");
    let ext_pipe = obj.remove("external-controller-pipe");
    let ext_mark = obj.remove("external-controller-routing-mark");
    let ext_doh = obj.remove("external-doh-server");

    if ext_ctrl.is_some()
        || ext_ui.is_some()
        || ext_ui_name.is_some()
        || ext_ui_url.is_some()
        || cors_origins.is_some()
        || cors_pna.is_some()
    {
        let ctrl_val = obj
            .entry("control".to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(ctrl_map) = ctrl_val.as_object_mut() {
            if !ctrl_map.contains_key("listen") {
                let addr = ext_ctrl
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "127.0.0.1:9090".into());
                ctrl_map.insert("listen".into(), Value::String(addr));
            }
            if let Some(sec) = secret {
                ctrl_map.entry("secret".to_owned()).or_insert(sec);
            }
            if let Some(ui) = ext_ui {
                ctrl_map.entry("external_ui".to_owned()).or_insert(ui);
            }
            if let Some(ui_n) = ext_ui_name {
                ctrl_map
                    .entry("external_ui_name".to_owned())
                    .or_insert(ui_n);
            }
            if let Some(ui_u) = ext_ui_url {
                ctrl_map.entry("external_ui_url".to_owned()).or_insert(ui_u);
            }
            if let Some(origins) = cors_origins {
                let arr = if origins.is_array() {
                    origins
                } else {
                    Value::Array(vec![origins])
                };
                ctrl_map
                    .entry("cors_allow_origins".to_owned())
                    .or_insert(arr);
            }
            if let Some(pna) = cors_pna {
                ctrl_map
                    .entry("cors_allow_private_network".to_owned())
                    .or_insert(pna);
            }
            if let Some(v) = ext_tls {
                ctrl_map.entry("tls_listen".to_owned()).or_insert(v);
            }
            if let Some(v) = ext_unix {
                ctrl_map.entry("unix_path".to_owned()).or_insert(v);
            }
            if let Some(v) = ext_pipe {
                ctrl_map.entry("pipe_path".to_owned()).or_insert(v);
            }
            if let Some(v) = ext_mark {
                ctrl_map.entry("routing_mark".to_owned()).or_insert(v);
            }
            if let Some(v) = ext_doh {
                ctrl_map.entry("doh_server".to_owned()).or_insert(v);
            }
        }
    }

    // Apply `env` map if present at top-level
    if let Some(Value::Object(env_map)) = obj.get("env").cloned() {
        apply_env_map(obj, &env_map);
    }

    // Normalize top-level Clash `rules` array into `routes` and `route.final`
    if let Some(Value::Array(clash_rules)) = obj.remove("rules") {
        let mut parsed_routes = obj
            .remove("routes")
            .and_then(|v| match v {
                Value::Array(a) => Some(a),
                _ => None,
            })
            .unwrap_or_default();
        let mut final_outbound: Option<String> = None;
        for item in clash_rules {
            match item {
                Value::String(line) => {
                    let (spec_opt, fin_opt) = kerlico_routing::parse_clash_rule_line(&line)?;
                    if let Some(spec) = spec_opt
                        && let Ok(val) = serde_json::to_value(spec)
                    {
                        parsed_routes.push(val);
                    }
                    if let Some(fin) = fin_opt {
                        final_outbound = Some(fin);
                    }
                }
                obj_val @ Value::Object(_) => parsed_routes.push(obj_val),
                _ => return Err(Error::Config("rules 元素须为字符串或规则对象".into())),
            }
        }
        obj.insert("routes".into(), Value::Array(parsed_routes));
        if let Some(fin) = final_outbound {
            let route_obj = obj
                .entry("route".to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(rmap) = route_obj.as_object_mut() {
                rmap.entry("final".to_owned()).or_insert(Value::String(fin));
            }
        }
    }

    // Normalize Clash string rules inside `sub-rules` / `sub_rules`
    for sub_key in ["sub-rules", "sub_rules"] {
        if let Some(Value::Object(sub_map)) = obj.get_mut(sub_key) {
            for (_name, arr_val) in sub_map.iter_mut() {
                if let Value::Array(items) = arr_val {
                    let mut converted = Vec::with_capacity(items.len());
                    for item in items.drain(..) {
                        match item {
                            Value::String(line) => {
                                let (spec_opt, _) = kerlico_routing::parse_clash_rule_line(&line)?;
                                if let Some(spec) = spec_opt
                                    && let Ok(val) = serde_json::to_value(spec)
                                {
                                    converted.push(val);
                                }
                            }
                            other => converted.push(other),
                        }
                    }
                    *items = converted;
                }
            }
        }
    }

    // Strip unknown top-level anchor helper keys (e.g. `.anchor` or `common_*`) so `unknown-keys` holds
    let known_top_keys = [
        "$schema",
        "version",
        "epoch",
        "accounts",
        "outbounds",
        "inbounds",
        "nodes",
        "local_inbounds",
        "lan_allowed_ips",
        "lan-allowed-ips",
        "lan_disallowed_ips",
        "lan-disallowed-ips",
        "port",
        "http-port",
        "socks_port",
        "socks-port",
        "mixed_port",
        "mixed-port",
        "redir_port",
        "redir-port",
        "tproxy_port",
        "tproxy-port",
        "allow_lan",
        "allow-lan",
        "bind_address",
        "bind-address",
        "mode",
        "sub_rules",
        "sub-rules",
        "tun",
        "dialer",
        "interface_name",
        "interface-name",
        "bind-interface",
        "routing_mark",
        "routing-mark",
        "disable_keep_alive",
        "disable-keep-alive",
        "disable-tcp-keep-alive",
        "keep_alive_idle",
        "keep-alive-idle",
        "tcp-keep-alive",
        "keep_alive_interval",
        "keep-alive-interval",
        "tcp-keep-alive-interval",
        "certificate",
        "certificate_providers",
        "certificate-providers",
        "limits",
        "telemetry",
        "device",
        "routes",
        "route",
        "rule_set",
        "rule-set",
        "rule_providers",
        "rule-providers",
        "geodata_mode",
        "geodata-mode",
        "geodata_loader",
        "geodata-loader",
        "geosite_matcher",
        "geosite-matcher",
        "geo_auto_update",
        "geo-auto-update",
        "geo_update_interval",
        "geo-update-interval",
        "geox_url",
        "geox-url",
        "geodata",
        "dns",
        "fakedns",
        "sniffer",
        "experimental",
        "cache_file",
        "cache-file",
        "profile",
        "proxy_groups",
        "proxy-groups",
        "proxy_providers",
        "proxy-providers",
        "log",
        "log_level",
        "log-level",
        "etag_support",
        "etag-support",
        "control",
        "ntp",
        "services",
        "http_clients",
        "http-clients",
        "network_namespaces",
        "network-namespaces",
        "observatory",
        "burst_observatory",
        "burst-observatory",
        "burstObservatory",
        "env",
    ];
    obj.retain(|k, _| known_top_keys.contains(&k.as_str()));
    Ok(())
}

pub fn apply_env_overrides(root: &mut Value) {
    let Some(obj) = root.as_object_mut() else {
        return;
    };
    let mut env_map = Map::new();
    for key in [
        "BOX_API",
        "CLASH_AGE_SECRET_KEY",
        "CLASH_CONFIG_FILE",
        "CLASH_CONFIG_STRING",
        "CLASH_HOME_DIR",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS",
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX",
        "CLASH_OVERRIDE_EXTERNAL_UI_DIR",
        "CLASH_OVERRIDE_SECRET",
        "CLASH_POST_DOWN",
        "CLASH_POST_UP",
        "DISABLE_EMBED_CA",
        "DISABLE_LOOPBACK_DETECTOR",
        "DISABLE_SYSTEM_HOSTS",
        "SAFE_PATHS",
        "SKIP_SAFE_PATH_CHECK",
        "XRAY_BROWSER_DIALER",
        "XRAY_CONE_DISABLED",
        "XRAY_LOCATION_ASSET",
        "XRAY_LOCATION_CERT",
        "XRAY_LOCATION_CONFDIR",
        "XRAY_LOCATION_CONFIG",
        "XRAY_TUN_FD",
        "XRAY_XUDP_BASEKEY",
    ] {
        if let Ok(val) = std::env::var(key)
            && !val.trim().is_empty()
        {
            env_map.insert(key.to_owned(), Value::String(val));
        }
    }
    apply_env_map(obj, &env_map);
}

fn apply_env_map(obj: &mut Map<String, Value>, env_map: &Map<String, Value>) {
    let get_env = |names: &[&str]| -> Option<String> {
        for n in names {
            if let Some(v) = env_map.get(*n).and_then(Value::as_str) {
                return Some(v.to_owned());
            }
        }
        None
    };

    let ctrl_listen = get_env(&[
        "CLASH_OVERRIDE_EXTERNAL_CONTROLLER",
        "clash-override-external-controller",
        "BOX_API",
        "box-api",
    ]);
    let ctrl_secret = get_env(&["CLASH_OVERRIDE_SECRET", "clash-override-secret"]);
    let ctrl_ui = get_env(&[
        "CLASH_OVERRIDE_EXTERNAL_UI_DIR",
        "clash-override-external-ui-dir",
    ]);
    if ctrl_listen.is_some() || ctrl_secret.is_some() || ctrl_ui.is_some() {
        let ctrl = obj
            .entry("control".to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(ctrl_map) = ctrl.as_object_mut() {
            if let Some(l) = ctrl_listen {
                ctrl_map.insert("listen".into(), Value::String(l));
            } else if !ctrl_map.contains_key("listen") {
                ctrl_map.insert("listen".into(), Value::String("127.0.0.1:9090".into()));
            }
            if let Some(s) = ctrl_secret {
                ctrl_map.insert("secret".into(), Value::String(s));
            }
            if let Some(u) = ctrl_ui {
                ctrl_map.insert("external_ui".into(), Value::String(u));
            }
        }
    }
}

pub fn merge_config_values(base: &mut Value, overlay: Value, is_tail: bool) {
    let (Some(base_obj), Value::Object(over_obj)) = (base.as_object_mut(), overlay.clone()) else {
        *base = overlay;
        return;
    };
    for (k, v) in over_obj {
        match k.as_str() {
            "inbounds" | "nodes" | "local_inbounds" => {
                if let Value::Array(new_items) = v {
                    let entry = base_obj
                        .entry(k)
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Some(arr) = entry.as_array_mut() {
                        for item in new_items {
                            let tag = item.get("tag").and_then(Value::as_str);
                            if let Some(t) = tag
                                && let Some(existing) = arr
                                    .iter_mut()
                                    .find(|e| e.get("tag").and_then(Value::as_str) == Some(t))
                            {
                                *existing = item;
                            } else {
                                arr.push(item);
                            }
                        }
                    }
                }
            }
            "outbounds" => {
                if let Value::Array(new_items) = v {
                    let entry = base_obj
                        .entry(k)
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Some(arr) = entry.as_array_mut() {
                        let mut prepend = Vec::new();
                        for item in new_items {
                            let tag = item.get("tag").and_then(Value::as_str);
                            if let Some(t) = tag
                                && let Some(existing) = arr
                                    .iter_mut()
                                    .find(|e| e.get("tag").and_then(Value::as_str) == Some(t))
                            {
                                *existing = item;
                            } else if is_tail {
                                arr.push(item);
                            } else {
                                prepend.push(item);
                            }
                        }
                        if !prepend.is_empty() {
                            prepend.append(arr);
                            *arr = prepend;
                        }
                    }
                }
            }
            _ => match (base_obj.get_mut(&k), v) {
                (Some(Value::Object(b_sub)), Value::Object(o_sub)) => {
                    for (sk, sv) in o_sub {
                        b_sub.insert(sk, sv);
                    }
                }
                (_, new_val) => {
                    base_obj.insert(k, new_val);
                }
            },
        }
    }
}

pub fn load_and_merge_configs(
    files: &[std::path::PathBuf],
    dirs: &[std::path::PathBuf],
    format: Option<&str>,
) -> Result<Value> {
    let mut all_paths: Vec<std::path::PathBuf> = files.to_vec();
    for dir in dirs {
        let rd = std::fs::read_dir(dir)?;
        let mut dir_files: Vec<std::path::PathBuf> = rd
            .filter_map(|e| e.ok().map(|de| de.path()))
            .filter(|p| {
                p.is_file()
                    && p.extension().and_then(|e| e.to_str()).is_some_and(|ext| {
                        matches!(
                            ext.to_ascii_lowercase().as_str(),
                            "json" | "jsonc" | "yaml" | "yml" | "toml" | "pb"
                        )
                    })
            })
            .collect();
        dir_files.sort();
        all_paths.extend(dir_files);
    }

    if all_paths.is_empty() {
        if let Ok(env_cfg) = std::env::var("CLASH_CONFIG_STRING")
            && !env_cfg.trim().is_empty()
        {
            let mut v = parse_config_value_with_format(env_cfg.as_bytes(), format)?;
            apply_env_overrides(&mut v);
            return Ok(v);
        }
        if let Ok(env_file) =
            std::env::var("CLASH_CONFIG_FILE").or_else(|_| std::env::var("XRAY_LOCATION_CONFIG"))
            && !env_file.trim().is_empty()
        {
            all_paths.push(std::path::PathBuf::from(env_file));
        }
    }

    if all_paths.is_empty() {
        return Err(Error::Config("未指定配置文件或配置目录".into()));
    }

    let mut merged: Option<Value> = None;
    for path in all_paths {
        let bytes = std::fs::read(&path)?;
        let val = parse_config_value_with_format(&bytes, format)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_tail = file_name.contains("tail");
        match &mut merged {
            None => merged = Some(val),
            Some(base) => merge_config_values(base, val, is_tail),
        }
    }
    let mut final_val = merged.unwrap_or_else(|| Value::Object(Map::new()));
    apply_env_overrides(&mut final_val);
    normalize_config_value(&mut final_val)?;
    Ok(final_val)
}

pub fn generate_json_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Kerlico Configuration Schema v2",
        "type": "object",
        "required": ["version", "outbounds"],
        "properties": {
            "$schema": { "type": "string" },
            "version": {
                "oneOf": [
                    { "type": "integer", "const": 2 },
                    { "type": "string" },
                    {
                        "type": "object",
                        "properties": {
                            "min": { "type": "string" },
                            "max": { "type": "string" }
                        }
                    }
                ]
            },
            "outbounds": { "type": "array" },
            "inbounds": { "type": "array" },
            "nodes": { "type": "array" },
            "local_inbounds": { "type": "array" },
            "routes": { "type": "array" },
            "route": { "type": "object" },
            "dns": { "type": "object" },
            "ntp": { "type": "object" },
            "control": { "type": "object" },
            "experimental": { "type": "object" }
        }
    })
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
        assert!(val.get("common_hc").is_none());
    }

    #[test]
    fn parses_toml_and_merges_by_tag() {
        let toml_raw = r#"
version = 2

[[outbounds]]
tag = "direct"
type = "direct"
"#;
        let mut base =
            parse_config_value_with_format(toml_raw.as_bytes(), Some("toml")).expect("parse toml");
        let overlay = serde_json::json!({
            "version": 2,
            "outbounds": [
                { "tag": "proxy-a", "type": "direct" }
            ]
        });
        merge_config_values(&mut base, overlay, false);
        assert_eq!(base["outbounds"][0]["tag"], "proxy-a");
        assert_eq!(base["outbounds"][1]["tag"], "direct");
    }

    #[test]
    fn normalizes_mihomo_yaml_rules_sub_rules_and_ports() {
        let yaml_raw = r#"
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: true
bind-address: "*"
mode: rule

proxies:
  - name: hk-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: secret

sub-rules:
  sub-tcp:
    - DOMAIN-SUFFIX,internal.example.com,hk-ss

rules:
  - PROCESS-NAME,curl,DIRECT
  - SUB-RULE,(NETWORK,tcp),sub-tcp
  - DOMAIN-SUFFIX,google.com,hk-ss
  - MATCH,DIRECT
"#;
        let val = parse_config_value(yaml_raw.as_bytes()).expect("parse mihomo yaml");
        assert_eq!(val["port"], 7890);
        assert_eq!(val["socks-port"], 7891);
        assert_eq!(val["mixed-port"], 7892);
        assert_eq!(val["outbounds"][0]["tag"], "hk-ss");
        assert_eq!(val["outbounds"][0]["type"], "shadowsocks");
        assert_eq!(val["routes"].as_array().unwrap().len(), 3);
        assert_eq!(val["route"]["final"], "DIRECT");
        let parsed = crate::parse(yaml_raw.as_bytes()).expect("deserialize into Config");
        assert_eq!(parsed.port, Some(7890));
        assert_eq!(parsed.socks_port, Some(7891));
        assert_eq!(parsed.sub_rules.get("sub-tcp").unwrap().len(), 1);
    }
}

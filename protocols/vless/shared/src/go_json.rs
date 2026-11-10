//! Go `encoding/json` struct matching for settings that Xray decodes with `json.Unmarshal`.

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Value};

/// A JSON object in document order, so a later key overrides an earlier one as it does in Go.
struct Pairs(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Ordered;
        impl<'de> Visitor<'de> for Ordered {
            type Value = Pairs;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, Value>()? {
                    pairs.push(pair);
                }
                Ok(Pairs(pairs))
            }
        }
        deserializer.deserialize_map(Ordered)
    }
}

/// `null` decodes to no object, as Go leaves a struct untouched. Anything but an object or `null` is an error.
pub(crate) fn object(text: &str) -> serde_json::Result<Option<Vec<(String, Value)>>> {
    Ok(serde_json::from_str::<Option<Pairs>>(text)?.map(|pairs| pairs.0))
}

/// Go matches keys to field names case-insensitively with Unicode simple folding. Only the two
/// non-ASCII characters that fold into ASCII letters can matter for the ASCII field names used here.
pub(crate) fn fold(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\u{212a}' => 'k',
            '\u{17f}' => 's',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// Keeps each known field under its canonical name with the last non-null value. Unknown keys are dropped
/// because Go ignores them, and `null` leaves a field as it was.
pub(crate) fn fields(pairs: Vec<(String, Value)>, names: &[&str]) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in pairs {
        let key = fold(&key);
        if let Some(name) = names.iter().find(|name| fold(name) == key) {
            if !value.is_null() {
                map.insert((*name).to_owned(), value);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_follow_go_matching() {
        let pairs = object(r#"{"MARK": 1, "mark": 2, "Other": 3, "interface": null, "tcpMPTCP": true}"#).unwrap().unwrap();
        let map = fields(pairs, &["mark", "interface", "tcpMptcp"]);
        assert_eq!(map.get("mark"), Some(&Value::from(2)));
        assert_eq!(map.get("tcpMptcp"), Some(&Value::Bool(true)));
        assert_eq!(map.len(), 2);
        assert!(object("null").unwrap().is_none());
        assert!(object("[]").is_err());
        assert_eq!(fold("\u{212a}ey"), "key");
    }
}

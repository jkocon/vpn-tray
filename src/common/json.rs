//! Wygodny dostęp do JSON-a demonów (pola bywają nieobecne albo null - jak `dict.get` w Pythonie).

pub use serde_json::Value;

static NULL: Value = Value::Null;

/// Pole obiektu albo null.
pub fn get<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&NULL)
}

/// Tekst albo "" (także dla null i innych typów).
pub fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Prawdziwość jak w Pythonie: false, null, 0, "", [] i {} to fałsz.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(t) => !t.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

pub fn b(v: &Value, key: &str) -> bool {
    truthy(get(v, key))
}

/// Liczba (int albo float) albo 0.
pub fn n(v: &Value, key: &str) -> f64 {
    get(v, key).as_f64().unwrap_or(0.0)
}

/// Elementy tablicy (pusta dla null/braku).
pub fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    get(v, key).as_array().map(Vec::as_slice).unwrap_or(&[])
}

/// Wartości obiektu (np. mapa peerów po kluczu publicznym).
pub fn values<'a>(v: &'a Value, key: &str) -> Vec<&'a Value> {
    get(v, key).as_object().map(|o| o.values().collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_and_null() {
        let v = json!({"a": null, "b": "x", "c": 0, "d": [1]});
        assert_eq!(s(&v, "a"), "");
        assert_eq!(s(&v, "b"), "x");
        assert!(!b(&v, "c"));
        assert!(b(&v, "d"));
        assert!(arr(&v, "zzz").is_empty());
        assert!(get(&NULL, "x").is_null());
    }
}

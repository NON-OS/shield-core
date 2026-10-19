//! JSON for the page, written by hand: the core's records carry no serde, and every value here
//! is a string, a number, a flag or a list of those.

use std::fmt::Write;

/// One JSON object, built field by field.
#[derive(Default)]
pub struct Json {
    out: String,
}

impl Json {
    pub fn obj() -> Json {
        Json::default()
    }

    fn key(mut self, name: &str) -> Json {
        self.out.push(if self.out.is_empty() { '{' } else { ',' });
        quote(&mut self.out, name);
        self.out.push(':');
        self
    }

    pub fn str(self, name: &str, value: &str) -> Json {
        let mut j = self.key(name);
        quote(&mut j.out, value);
        j
    }

    pub fn opt(self, name: &str, value: Option<&str>) -> Json {
        match value {
            Some(v) => self.str(name, v),
            None => self.raw(name, "null"),
        }
    }

    pub fn num(self, name: &str, value: impl Into<u64>) -> Json {
        let mut j = self.key(name);
        let _ = write!(j.out, "{}", value.into());
        j
    }

    pub fn flag(self, name: &str, value: bool) -> Json {
        self.raw(name, if value { "true" } else { "false" })
    }

    pub fn strs(self, name: &str, values: &[String]) -> Json {
        let list: Vec<String> = values.iter().map(|v| text(v)).collect();
        self.raw(name, &format!("[{}]", list.join(",")))
    }

    /// A value already written as JSON, such as a nested object or a list of them.
    pub fn raw(self, name: &str, json: &str) -> Json {
        let mut j = self.key(name);
        j.out.push_str(json);
        j
    }

    pub fn done(mut self) -> String {
        if self.out.is_empty() {
            self.out.push('{');
        }
        self.out.push('}');
        self.out
    }
}

/// A string as a JSON string literal.
pub fn text(value: &str) -> String {
    let mut out = String::new();
    quote(&mut out, value);
    out
}

/// A list of values already written as JSON.
pub fn list(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(","))
}

fn quote(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

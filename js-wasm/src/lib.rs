use serde::{Deserialize, Serialize};
#[cfg(any(target_family = "wasm", test))]
use yara_x::{
    Compiler as YaraCompiler, MetaValue, PatternKind, Rules as YaraRules,
    Scanner as YaraScanner,
};

#[cfg(target_family = "wasm")]
use js_sys::{Function, Reflect};
#[cfg(target_family = "wasm")]
use std::sync::Arc;
#[cfg(all(not(target_family = "wasm"), test))]
use std::time::Duration;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ScanResult {
    valid: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
    matches: Vec<RuleMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RuleMatch {
    identifier: String,
    namespace: String,
    is_global: bool,
    is_private: bool,
    tags: Vec<String>,
    metadata: Vec<MetadataEntry>,
    patterns: Vec<PatternMatchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct MetadataEntry {
    identifier: String,
    value: MetadataValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
enum MetadataValue {
    Integer(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PatternMatchResult {
    identifier: String,
    kind: String,
    is_private: bool,
    matches: Vec<PatternData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PatternData {
    offset: usize,
    length: usize,
    xor_key: Option<u8>,
}

#[cfg(test)]
#[derive(Debug)]
struct CompileOutcome {
    warnings: Vec<String>,
    errors: Vec<String>,
    rules: Option<YaraRules>,
}

#[cfg(test)]
fn scan_rules(rule_sources: &[String], payload: &[u8]) -> ScanResult {
    let compile_outcome = compile_rules(rule_sources);

    if !compile_outcome.errors.is_empty() {
        return ScanResult {
            valid: false,
            errors: compile_outcome.errors,
            warnings: compile_outcome.warnings,
            matches: vec![],
        };
    }

    let Some(rules) = compile_outcome.rules else {
        return ScanResult {
            valid: false,
            errors: vec!["internal error: rules were not built".to_owned()],
            warnings: compile_outcome.warnings,
            matches: vec![],
        };
    };

    scan_compiled_rules(
        &rules,
        payload,
        None,
        None,
        None,
        compile_outcome.warnings,
    )
}

#[cfg(any(target_family = "wasm", test))]
fn scan_compiled_rules(
    rules: &YaraRules,
    payload: &[u8],
    timeout_ms: Option<u64>,
    max_matches_per_pattern: Option<usize>,
    external_globals: Option<&[(String, serde_json::Value)]>,
    warnings: Vec<String>,
) -> ScanResult {
    let mut scanner = YaraScanner::new(rules);
    #[cfg(not(target_family = "wasm"))]
    if let Some(ms) = timeout_ms {
        scanner.set_timeout(Duration::from_millis(ms));
    }
    #[cfg(target_family = "wasm")]
    {
        let _ = timeout_ms;
        scanner.console_log(|message| emit_console_log(&message));
    }

    if let Some(limit) = max_matches_per_pattern {
        scanner.max_matches_per_pattern(limit);
    }

    if let Some(globals) = external_globals {
        for (identifier, value) in globals {
            if let Err(err) =
                scanner.set_global(identifier.as_str(), value.clone())
            {
                return ScanResult {
                    valid: false,
                    errors: vec![format!(
                        "failed to set global `{identifier}`: {err}"
                    )],
                    warnings,
                    matches: vec![],
                };
            }
        }
    }

    match scanner.scan(payload) {
        Ok(scan_results) => {
            let matches = scan_results
                .matching_rules()
                .include_private(true)
                .map(|rule| {
                    let metadata = rule
                        .metadata()
                        .map(|(identifier, value)| MetadataEntry {
                            identifier: identifier.to_owned(),
                            value: metadata_value(value),
                        })
                        .collect::<Vec<_>>();

                    let patterns = rule
                        .patterns()
                        .include_private(true)
                        .filter_map(|pattern| {
                            let pattern_matches = pattern
                                .matches()
                                .map(|entry| {
                                    let range = entry.range();
                                    PatternData {
                                        offset: range.start,
                                        length: range.end - range.start,
                                        xor_key: entry.xor_key(),
                                    }
                                })
                                .collect::<Vec<_>>();

                            if pattern_matches.is_empty() {
                                None
                            } else {
                                Some(PatternMatchResult {
                                    identifier: pattern
                                        .identifier()
                                        .to_owned(),
                                    kind: pattern_kind(pattern.kind())
                                        .to_owned(),
                                    is_private: pattern.is_private(),
                                    matches: pattern_matches,
                                })
                            }
                        })
                        .collect::<Vec<_>>();

                    RuleMatch {
                        identifier: rule.identifier().to_owned(),
                        namespace: rule.namespace().to_owned(),
                        is_global: rule.is_global(),
                        is_private: rule.is_private(),
                        tags: rule
                            .tags()
                            .map(|tag| tag.identifier().to_owned())
                            .collect::<Vec<_>>(),
                        metadata,
                        patterns,
                    }
                })
                .collect::<Vec<_>>();

            ScanResult { valid: true, errors: vec![], warnings, matches }
        }
        Err(err) => ScanResult {
            valid: false,
            errors: vec![format!("scan failed: {err}")],
            warnings,
            matches: vec![],
        },
    }
}

#[cfg(target_family = "wasm")]
fn collect_rule_warnings(rules: &YaraRules) -> Vec<String> {
    rules.warnings().iter().map(ToString::to_string).collect::<Vec<_>>()
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_name = Compiler)]
pub struct WasmCompiler {
    inner: Option<YaraCompiler<'static>>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_class = Compiler)]
impl WasmCompiler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { inner: Some(YaraCompiler::new()) }
    }

    #[wasm_bindgen(js_name = addSource)]
    pub fn add_source(&mut self, source: &str) -> Result<(), JsValue> {
        self.inner_mut()?
            .add_source(source)
            .map(|_| ())
            .map_err(|err| js_error(err.to_string()))
    }

    #[wasm_bindgen(js_name = newNamespace)]
    pub fn new_namespace(&mut self, namespace: &str) -> Result<(), JsValue> {
        self.inner_mut()?.new_namespace(namespace);
        Ok(())
    }

    #[wasm_bindgen(js_name = defineGlobal)]
    pub fn define_global(
        &mut self,
        identifier: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        let value = parse_variable_value_js(value)?;
        self.inner_mut()?
            .define_global(identifier, value)
            .map(|_| ())
            .map_err(|err| js_error(err.to_string()))
    }

    #[wasm_bindgen(getter)]
    pub fn errors(&self) -> Result<Vec<String>, JsValue> {
        Ok(self
            .inner_ref()?
            .errors()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>())
    }

    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> Result<Vec<String>, JsValue> {
        Ok(self
            .inner_ref()?
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>())
    }

    pub fn build(&mut self) -> Result<WasmRules, JsValue> {
        {
            let compiler = self.inner_ref()?;
            let errors = compiler
                .errors()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if !errors.is_empty() {
                return Err(js_error(errors.join("\n\n")));
            }
        }

        let compiler = self
            .inner
            .take()
            .ok_or_else(|| js_error("compiler has already been consumed"))?;
        let rules = compiler.build();
        Ok(WasmRules { inner: Arc::new(rules) })
    }

    fn inner_ref(&self) -> Result<&YaraCompiler<'static>, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_error("compiler has already been consumed"))
    }

    fn inner_mut(&mut self) -> Result<&mut YaraCompiler<'static>, JsValue> {
        self.inner
            .as_mut()
            .ok_or_else(|| js_error("compiler has already been consumed"))
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_name = Rules)]
pub struct WasmRules {
    inner: Arc<YaraRules>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_class = Rules)]
impl WasmRules {
    #[wasm_bindgen(js_name = scanner)]
    pub fn scanner(&self) -> WasmScanner {
        WasmScanner {
            rules: Arc::clone(&self.inner),
            timeout_ms: None,
            max_matches_per_pattern: None,
            globals: vec![],
        }
    }

    #[wasm_bindgen(js_name = scan)]
    pub fn scan(&self, payload: &[u8]) -> Result<JsValue, JsValue> {
        let result = scan_compiled_rules(
            &self.inner,
            payload,
            None,
            None,
            None,
            collect_rule_warnings(&self.inner),
        );
        serde_wasm_bindgen::to_value(&result).map_err(|err| {
            js_error(format!("failed to serialize result: {err}"))
        })
    }

    #[wasm_bindgen(getter)]
    pub fn warnings(&self) -> Vec<String> {
        self.inner
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_name = Scanner)]
pub struct WasmScanner {
    rules: Arc<YaraRules>,
    timeout_ms: Option<u64>,
    max_matches_per_pattern: Option<usize>,
    globals: Vec<(String, serde_json::Value)>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen(js_class = Scanner)]
impl WasmScanner {
    #[wasm_bindgen(constructor)]
    pub fn new(rules: &WasmRules) -> Self {
        Self {
            rules: Arc::clone(&rules.inner),
            timeout_ms: None,
            max_matches_per_pattern: None,
            globals: vec![],
        }
    }

    #[wasm_bindgen(js_name = setTimeoutMs)]
    pub fn set_timeout_ms(&mut self, timeout_ms: u32) {
        self.timeout_ms = Some(timeout_ms as u64);
    }

    #[wasm_bindgen(js_name = setMaxMatchesPerPattern)]
    pub fn set_max_matches_per_pattern(&mut self, n: usize) {
        self.max_matches_per_pattern = Some(n);
    }

    #[wasm_bindgen(js_name = setGlobal)]
    pub fn set_global(
        &mut self,
        identifier: &str,
        value: JsValue,
    ) -> Result<(), JsValue> {
        let value = parse_variable_value_js(value)?;
        let mut probe = YaraScanner::new(&self.rules);
        probe
            .set_global(identifier, value.clone())
            .map(|_| ())
            .map_err(|err| js_error(err.to_string()))?;

        if let Some((_, existing_value)) = self
            .globals
            .iter_mut()
            .find(|(existing_identifier, _)| existing_identifier == identifier)
        {
            *existing_value = value;
        } else {
            self.globals.push((identifier.to_owned(), value));
        }

        Ok(())
    }

    pub fn scan(&self, payload: &[u8]) -> Result<JsValue, JsValue> {
        let result = scan_compiled_rules(
            &self.rules,
            payload,
            self.timeout_ms,
            self.max_matches_per_pattern,
            Some(&self.globals),
            collect_rule_warnings(&self.rules),
        );
        serde_wasm_bindgen::to_value(&result).map_err(|err| {
            js_error(format!("failed to serialize result: {err}"))
        })
    }
}

#[cfg(test)]
fn compile_rules(rule_sources: &[String]) -> CompileOutcome {
    let mut compiler = YaraCompiler::new();

    for rule_source in rule_sources {
        let _ = compiler.add_source(rule_source.as_str());
    }

    let warnings = compiler
        .warnings()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let errors =
        compiler.errors().iter().map(ToString::to_string).collect::<Vec<_>>();

    let rules = if errors.is_empty() { Some(compiler.build()) } else { None };

    CompileOutcome { warnings, errors, rules }
}

#[cfg(target_family = "wasm")]
fn emit_console_log(message: &str) {
    let global = js_sys::global();
    let console = match Reflect::get(&global, &JsValue::from_str("console")) {
        Ok(console) => console,
        Err(_) => return,
    };
    let log = match Reflect::get(&console, &JsValue::from_str("log")) {
        Ok(log) => log,
        Err(_) => return,
    };
    let log = match log.dyn_into::<Function>() {
        Ok(log) => log,
        Err(_) => return,
    };
    let _ = log.call1(&console, &JsValue::from_str(message));
}

#[cfg(any(target_family = "wasm", test))]
fn metadata_value(value: MetaValue<'_>) -> MetadataValue {
    match value {
        MetaValue::Integer(i) => MetadataValue::Integer(i),
        MetaValue::Float(f) => MetadataValue::Float(f),
        MetaValue::Bool(b) => MetadataValue::Bool(b),
        MetaValue::String(s) => MetadataValue::String(s.to_owned()),
        MetaValue::Bytes(bytes) => MetadataValue::Bytes(bytes.to_vec()),
    }
}

#[cfg(any(target_family = "wasm", test))]
fn pattern_kind(kind: PatternKind) -> &'static str {
    match kind {
        PatternKind::Text => "text",
        PatternKind::Hex => "hex",
        PatternKind::Regexp => "regexp",
    }
}

#[cfg(target_family = "wasm")]
fn parse_variable_value_js(
    value: JsValue,
) -> Result<serde_json::Value, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|err| {
        js_error(format!("global value must be JSON-compatible: {err}"))
    })
}

#[cfg(target_family = "wasm")]
fn js_error(message: impl Into<String>) -> JsValue {
    js_sys::Error::new(&message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_rule() -> String {
        r#"
        rule sample : malware demo {
            meta:
                author = "linus"
                score = 7
                active = true
            strings:
                $a = "abc"
            condition:
                $a
        }
        "#
        .to_owned()
    }

    #[test]
    fn validates_rules() {
        let rule = valid_rule();
        let result = compile_rules(&[rule]);

        assert!(result.errors.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn reports_syntax_errors() {
        let invalid_rule =
            "rule bad { strings: $a = \"abc\" condition: $a and }".to_owned();
        let result = compile_rules(&[invalid_rule]);

        assert!(!result.errors.is_empty());
    }

    #[test]
    fn scans_and_returns_metadata_and_matches() {
        let scan_result = scan_rules(&[valid_rule()], b"zzzabczzz");

        assert!(scan_result.valid);
        assert_eq!(scan_result.matches.len(), 1);

        let rule = &scan_result.matches[0];
        assert_eq!(rule.identifier, "sample");
        assert_eq!(rule.namespace, "default");
        assert_eq!(rule.tags, vec!["malware".to_owned(), "demo".to_owned()]);
        assert_eq!(rule.metadata.len(), 3);

        let pattern = &rule.patterns[0];
        assert_eq!(pattern.identifier, "$a");
        assert_eq!(pattern.kind, "text");
        assert_eq!(pattern.matches.len(), 1);

        let matched = &pattern.matches[0];
        assert_eq!(matched.offset, 3);
        assert_eq!(matched.length, 3);
    }
}

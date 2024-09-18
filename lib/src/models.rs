use crate::compiler::{IdentId, PatternId, RuleInfo};
use crate::scanner::{ScanContext, ScannedData};
use crate::{compiler, scanner, Rules};
use bstr::{BStr, ByteSlice};
use serde::Serialize;
use std::ops::Range;
use std::slice::Iter;

/// A structure that describes a rule.
pub struct Rule<'a, 'r> {
    pub(crate) ctx: Option<&'a ScanContext<'r>>,
    pub(crate) data: Option<&'a ScannedData<'a>>,
    pub(crate) rules: &'r Rules,
    pub(crate) rule_info: &'r RuleInfo,
}

impl<'a, 'r> Rule<'a, 'r> {
    /// Returns the rule's name.
    pub fn identifier(&self) -> &'r str {
        self.rules.ident_pool().get(self.rule_info.ident_id).unwrap()
    }

    /// Returns the rule's namespace.
    pub fn namespace(&self) -> &'r str {
        self.rules.ident_pool().get(self.rule_info.namespace_ident_id).unwrap()
    }

    /// Returns the metadata associated to this rule.
    pub fn metadata(&self) -> Metadata<'a, 'r> {
        Metadata {
            rules: self.rules,
            iterator: self.rule_info.metadata.iter(),
            len: self.rule_info.metadata.len(),
        }
    }

    /// Returns the tags associated to this rule.
    pub fn tags(&self) -> Tags<'a, 'r> {
        Tags {
            rules: self.rules,
            iterator: self.rule_info.tags.iter(),
            len: self.rule_info.tags.len(),
        }
    }

    /// Returns the patterns defined by this rule.
    pub fn patterns(&self) -> Patterns<'a, 'r> {
        Patterns {
            ctx: self.ctx,
            rules: self.rules,
            data: self.data,
            iterator: self.rule_info.patterns.iter(),
            len: self.rule_info.patterns.len(),
        }
    }
}

/// A metadata value.
#[derive(Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MetaValue<'r> {
    /// Integer value.
    Integer(i64),
    /// Float value.
    Float(f64),
    /// Bool value.
    Bool(bool),
    /// A valid UTF-8 string.
    String(&'r str),
    /// An arbitrary string. Used when the value contains invalid UTF-8
    /// characters.
    Bytes(&'r BStr),
}

/// Iterator that returns the metadata associated to a rule.
///
/// The iterator returns (`&str`, [`MetaValue`]) pairs, where the first item
/// is the identifier, and the second one the metadata value.
pub struct Metadata<'a, 'r> {
    rules: &'r Rules,
    iterator: Iter<'a, (IdentId, compiler::MetaValue)>,
    len: usize,
}

impl<'a, 'r> Metadata<'a, 'r> {
    /// Returns the metadata as a [`serde_json::Value`].
    ///
    /// The returned value is an array of tuples `(ident, value)` with all
    /// the metadata associated to the rule.
    ///
    /// ```rust
    /// # use yara_x;
    /// let rules = yara_x::compile(r#"
    /// rule test {
    ///   meta:
    ///     some_int = 1
    ///     some_bool = true
    ///     some_str = "foo"
    ///     some_bytes = "\x01\x02\x03"
    ///   condition:
    ///     true
    /// }
    /// "#).unwrap();
    ///
    /// let mut scanner = yara_x::Scanner::new(&rules);
    ///
    /// let scan_results = scanner
    ///     .scan(&[])
    ///     .unwrap();
    ///
    /// let matching_rule = scan_results
    ///     .matching_rules()
    ///     .next()
    ///     .unwrap();
    ///
    /// assert_eq!(
    ///     matching_rule.metadata().into_json(),
    ///     serde_json::json!([
    ///         ("some_int", 1),
    ///         ("some_bool", true),
    ///         ("some_str", "foo"),
    ///         ("some_bytes", [0x01, 0x02, 0x03]),
    ///     ])
    /// );
    /// ```
    pub fn into_json(self) -> serde_json::Value {
        let v: Vec<(&'r str, MetaValue<'r>)> = self.collect();
        serde_json::value::to_value(v).unwrap()
    }

    /// Returns `true` if the rule doesn't have any metadata.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iterator.len() == 0
    }
}

impl<'a, 'r> Iterator for Metadata<'a, 'r> {
    type Item = (&'r str, MetaValue<'r>);

    fn next(&mut self) -> Option<Self::Item> {
        let (ident_id, value) = self.iterator.next()?;

        let ident = self.rules.ident_pool().get(*ident_id).unwrap();

        let value = match value {
            compiler::MetaValue::Bool(b) => MetaValue::Bool(*b),
            compiler::MetaValue::Integer(i) => MetaValue::Integer(*i),
            compiler::MetaValue::Float(f) => MetaValue::Float(*f),
            compiler::MetaValue::String(id) => {
                let s = self.rules.lit_pool().get(*id).unwrap();
                // We can be sure that s is a valid UTF-8 string, because
                // the type of meta is MetaValue::String.
                let s = unsafe { s.to_str_unchecked() };
                MetaValue::String(s)
            }
            compiler::MetaValue::Bytes(id) => {
                MetaValue::Bytes(self.rules.lit_pool().get(*id).unwrap())
            }
        };

        Some((ident, value))
    }
}

impl<'a, 'r> ExactSizeIterator for Metadata<'a, 'r> {
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

/// An iterator that returns the tags defined by a rule.
pub struct Tags<'a, 'r> {
    rules: &'r Rules,
    iterator: Iter<'a, IdentId>,
    len: usize,
}

impl<'a, 'r> Tags<'a, 'r> {
    /// Returns `true` if the rule doesn't have any tags.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iterator.len() == 0
    }
}

impl<'a, 'r> Iterator for Tags<'a, 'r> {
    type Item = Tag<'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let ident_id = self.iterator.next()?;
        Some(Tag { rules: self.rules, ident_id: *ident_id })
    }
}

impl<'a, 'r> ExactSizeIterator for Tags<'a, 'r> {
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

/// Represents a tag defined by a rule.
pub struct Tag<'r> {
    rules: &'r Rules,
    ident_id: IdentId,
}

impl<'r> Tag<'r> {
    /// Returns the tag's identifier.
    pub fn identifier(&self) -> &'r str {
        self.rules.ident_pool().get(self.ident_id).unwrap()
    }
}

/// An iterator that returns the patterns defined by a rule.
pub struct Patterns<'a, 'r> {
    ctx: Option<&'a ScanContext<'r>>,
    data: Option<&'a ScannedData<'a>>,
    rules: &'r Rules,
    iterator: Iter<'a, (IdentId, PatternId)>,
    len: usize,
}

impl<'a, 'r> Iterator for Patterns<'a, 'r> {
    type Item = Pattern<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let (ident_id, pattern_id) = self.iterator.next()?;
        Some(Pattern {
            ctx: self.ctx,
            rules: self.rules,
            data: self.data,
            pattern_id: *pattern_id,
            ident_id: *ident_id,
        })
    }
}

impl<'a, 'r> ExactSizeIterator for Patterns<'a, 'r> {
    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

/// Represents a pattern defined by a rule.
pub struct Pattern<'a, 'r> {
    ctx: Option<&'a ScanContext<'r>>,
    data: Option<&'a ScannedData<'a>>,
    rules: &'r Rules,
    pattern_id: PatternId,
    ident_id: IdentId,
}

impl<'a, 'r> Pattern<'a, 'r> {
    /// Returns the pattern's identifier (e.g: $a, $b).
    pub fn identifier(&self) -> &'r str {
        self.rules.ident_pool().get(self.ident_id).unwrap()
    }

    /// Returns the matches found for this pattern.
    pub fn matches(&self) -> Matches<'a> {
        Matches {
            data: self.data,
            iterator: self.ctx.and_then(|ctx| {
                ctx.pattern_matches
                    .get(self.pattern_id)
                    .map(|matches| matches.iter())
            }),
        }
    }
}

/// Iterator that returns the matches for a pattern.
pub struct Matches<'a> {
    data: Option<&'a ScannedData<'a>>,
    iterator: Option<Iter<'a, scanner::Match>>,
}

impl<'a> Iterator for Matches<'a> {
    type Item = Match<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let iter = self.iterator.as_mut()?;
        Some(Match { data: self.data?, inner: iter.next()? })
    }
}

impl<'a> ExactSizeIterator for Matches<'a> {
    fn len(&self) -> usize {
        self.iterator.as_ref().map_or(0, |it| it.len())
    }
}

/// Represents a match.
pub struct Match<'a> {
    data: &'a ScannedData<'a>,
    inner: &'a scanner::Match,
}

impl<'a> Match<'a> {
    /// Range within the original data where the match occurred.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.inner.range.clone()
    }

    /// Slice containing the data that matched.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data.as_ref().get(self.inner.range.clone()).unwrap()
    }

    /// XOR key used for decrypting the data if the pattern had the `xor`
    /// modifier, or `None` if otherwise.
    #[inline]
    pub fn xor_key(&self) -> Option<u8> {
        self.inner.xor_key
    }
}

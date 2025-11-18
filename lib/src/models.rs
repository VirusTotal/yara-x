use std::ops::Range;
use std::slice::Iter;

use bstr::{BStr, ByteSlice};
use serde::{Deserialize, Serialize};

use crate::compiler::{IdentId, PatternId, PatternInfo, RuleInfo};
use crate::scanner::{ScanContext, ScanState};
use crate::{compiler, scanner, Rules};

/// Kinds of patterns.
#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum PatternKind {
    /// The pattern is a plain text string.
    Text,
    /// The pattern is a hex pattern (e.g: { 01 02 03 })
    Hex,
    /// The pattern is a regular expression.
    Regexp,
}

/// A structure that describes a rule.
pub struct Rule<'a, 'r> {
    pub(crate) ctx: Option<&'a ScanContext<'r, 'a>>,
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

    /// Returns true if the rule is global.
    pub fn is_global(&self) -> bool {
        self.rule_info.is_global
    }

    /// Returns true if the rule is private.
    pub fn is_private(&self) -> bool {
        self.rule_info.is_private
    }

    /// Returns the tags associated to this rule.
    pub fn tags(&self) -> Tags<'a, 'r> {
        Tags {
            rules: self.rules,
            iterator: self.rule_info.tags.iter(),
            len: self.rule_info.tags.len(),
        }
    }

    /// Returns an iterator over the patterns defined for this rule.
    ///
    /// By default, the iterator yields only public patterns. Use
    /// [`Patterns::include_private`] if you want to include private patterns
    /// as well.
    pub fn patterns(&self) -> Patterns<'a, 'r> {
        Patterns {
            ctx: self.ctx,
            rules: self.rules,
            include_private: false,
            iterator: self.rule_info.patterns.iter(),
            len_non_private: self.rule_info.patterns.len()
                - self.rule_info.num_private_patterns,
            len_private: self.rule_info.num_private_patterns,
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

impl<'r> Metadata<'_, 'r> {
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

impl<'r> Iterator for Metadata<'_, 'r> {
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

impl ExactSizeIterator for Metadata<'_, '_> {
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

impl Tags<'_, '_> {
    /// Returns `true` if the rule doesn't have any tags.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iterator.len() == 0
    }
}

impl<'r> Iterator for Tags<'_, 'r> {
    type Item = Tag<'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let ident_id = self.iterator.next()?;
        Some(Tag { rules: self.rules, ident_id: *ident_id })
    }
}

impl ExactSizeIterator for Tags<'_, '_> {
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
///
/// By default, the iterator yields only public patterns. Use
/// [`Patterns::include_private`] if you want to include private patterns
/// as well.
pub struct Patterns<'a, 'r> {
    ctx: Option<&'a ScanContext<'r, 'a>>,
    rules: &'r Rules,
    iterator: Iter<'a, PatternInfo>,
    /// True if the iterator should yield all patterns, including the
    /// private ones. If false, only the non-private patterns are
    /// yielded.
    include_private: bool,
    /// Number of private patterns that remain to be yielded.
    len_private: usize,
    /// Number of non-private patterns that remain to be yielded.
    len_non_private: usize,
}

impl Patterns<'_, '_> {
    /// Specifies whether the iterator should yield private patterns.
    ///
    /// This does not reset the iterator to its initial state, the iterator will
    /// continue from its current position.
    pub fn include_private(mut self, yes: bool) -> Self {
        self.include_private = yes;
        self
    }
}

impl ExactSizeIterator for Patterns<'_, '_> {
    #[inline]
    fn len(&self) -> usize {
        if self.include_private {
            self.len_non_private + self.len_private
        } else {
            self.len_non_private
        }
    }
}

impl<'a, 'r> Iterator for Patterns<'a, 'r> {
    type Item = Pattern<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let pattern = self.iterator.next()?;

            if pattern.is_private {
                self.len_private -= 1;
            } else {
                self.len_non_private -= 1;
            }

            if self.include_private || !pattern.is_private {
                return Some(Pattern {
                    ctx: self.ctx,
                    rules: self.rules,
                    ident_id: pattern.ident_id,
                    pattern_id: pattern.pattern_id,
                    kind: pattern.kind,
                    is_private: pattern.is_private,
                });
            }
        }
    }
}

/// Represents a pattern defined by a rule.
pub struct Pattern<'a, 'r> {
    ctx: Option<&'a ScanContext<'r, 'a>>,
    rules: &'r Rules,
    ident_id: IdentId,
    pattern_id: PatternId,
    kind: PatternKind,
    is_private: bool,
}

impl<'a, 'r> Pattern<'a, 'r> {
    /// Returns the pattern's identifier (e.g: $a, $b).
    pub fn identifier(&self) -> &'r str {
        self.rules.ident_pool().get(self.ident_id).unwrap()
    }

    /// Returns the kind of this pattern.
    #[inline]
    pub fn kind(&self) -> PatternKind {
        self.kind
    }

    /// Returns true if the pattern is private.
    #[inline]
    pub fn is_private(&self) -> bool {
        self.is_private
    }

    /// Returns the matches found for this pattern.
    pub fn matches(&self) -> Matches<'a, 'r> {
        Matches {
            ctx: self.ctx,
            iterator: self.ctx.and_then(|ctx| {
                ctx.pattern_matches
                    .get(self.pattern_id)
                    .map(|matches| matches.iter())
            }),
        }
    }
}

/// Iterator that returns the matches for a pattern.
pub struct Matches<'a, 'r> {
    ctx: Option<&'a ScanContext<'r, 'a>>,
    iterator: Option<Iter<'a, scanner::Match>>,
}

impl<'a, 'r> Iterator for Matches<'a, 'r> {
    type Item = Match<'a, 'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let iter = self.iterator.as_mut()?;
        Some(Match { ctx: self.ctx?, inner: iter.next()? })
    }
}

impl ExactSizeIterator for Matches<'_, '_> {
    fn len(&self) -> usize {
        self.iterator.as_ref().map_or(0, |it| it.len())
    }
}

/// Represents a match.
pub struct Match<'a, 'r> {
    ctx: &'a ScanContext<'r, 'a>,
    inner: &'a scanner::Match,
}

impl<'a> Match<'a, '_> {
    /// Range within the original data where the match occurred.
    #[inline]
    pub fn range(&self) -> Range<usize> {
        self.inner.range.clone()
    }

    /// Slice containing the data that matched.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        let data = match &self.ctx.scan_state {
            ScanState::Finished(snippets) => snippets.get(self.range()),
            _ => None,
        };

        data.unwrap()
    }

    /// XOR key used for decrypting the data if the pattern had the `xor`
    /// modifier, or `None` if otherwise.
    #[inline]
    pub fn xor_key(&self) -> Option<u8> {
        self.inner.xor_key
    }
}

use std::collections::HashMap;

use crate::ast::{Ident, Span};
use crate::cst::CSTNode;
use crate::report::ReportBuilder;

/// A structure that holds information about the parsing process.
pub(crate) struct Context<'src, 'rb> {
    /// Contains the pattern identifiers declared by the rule that is being
    /// currently parsed. The map is filled during the processing of the
    /// patterns (a.k.a. strings) section of the rule. Identifiers are stored
    /// without the `$` prefix.
    pub(crate) declared_patterns: HashMap<&'src str, Ident<'src>>,

    /// While parsing a pattern declaration this holds its identifier.
    pub(crate) current_pattern: Option<Ident<'src>>,

    /// Used for building error messages and warnings.
    pub(crate) report_builder: &'rb ReportBuilder,
}

impl<'src, 'rb> Context<'src, 'rb> {
    pub(crate) fn new(report_builder: &'rb ReportBuilder) -> Self {
        Self {
            declared_patterns: HashMap::new(),
            current_pattern: None,
            report_builder,
        }
    }

    /// Returns the identifier of the pattern that is currently being parsed.
    ///
    /// # Panics
    ///
    /// Panics if called at some point where a pattern is not being parsed,
    /// which means that should be called only from `pattern_from_cst` or any
    /// other function under `pattern_from_cst` in the call tree.
    pub(crate) fn current_pattern_ident(&self) -> String {
        self.current_pattern.as_ref().unwrap().name.to_string()
    }

    /// Creates a new [`Span`] from [`CSTNode`].
    pub(crate) fn span(&self, node: &CSTNode) -> Span {
        let span = node.as_span();
        Span::new(
            self.report_builder.current_source_id().unwrap(),
            span.start(),
            span.end(),
        )
    }
}

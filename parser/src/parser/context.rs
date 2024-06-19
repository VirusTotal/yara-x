use std::collections::{HashMap, HashSet};

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

    /// Similarly to `declared_patterns` this is filled with the identifiers
    /// of the patterns declared by the current rule. However, during the
    /// parsing of the rule's condition, identifiers are removed from this
    /// set as they are used in the condition.
    ///
    /// For example, if `$a` appears in the condition, `a` is removed from
    /// this set, if `them` appears, all identifiers are removed because this
    /// keyword refers to all the identifiers, if a tuple (`$a*`, `$b*`)
    /// appears in the condition, all identifiers starting with `a` and `b`
    /// are removed.
    ///
    /// After the whole condition is parsed, the remaining identifiers are
    /// the unused ones.
    pub(crate) unused_patterns: HashSet<&'src str>,

    /// Boolean that indicates if the parser is currently inside the expression
    /// of a `for .. of .. : (<expr>)` statement.
    pub(crate) inside_for_of: bool,

    /// While parsing a pattern declaration this holds its identifier.
    pub(crate) current_pattern: Option<Ident<'src>>,

    /// Used for building error messages and warnings.
    pub(crate) report_builder: &'rb ReportBuilder,
}

impl<'src, 'rb> Context<'src, 'rb> {
    pub(crate) fn new(report_builder: &'rb ReportBuilder) -> Self {
        Self {
            inside_for_of: false,
            declared_patterns: HashMap::new(),
            unused_patterns: HashSet::new(),
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

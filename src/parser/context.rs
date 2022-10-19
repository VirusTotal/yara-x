use crate::parser::warnings::Warning;
use crate::parser::Ident;
use std::collections::{HashMap, HashSet};

use super::report::ReportBuilder;

/// A structure that describes a YARA source code.
#[derive(Debug)]
pub(crate) struct SourceCode<'src> {
    /// A reference to the code itself in text form.
    pub text: &'src str,
    /// An optional string that tells which is the origin of the code. Usually
    /// a file path.
    pub origin: Option<std::string::String>,
}

/// A structure that holds information about the parsing process.
pub(crate) struct Context<'src> {
    /// The source code being parsed.
    pub(crate) src: SourceCode<'src>,

    /// Contains the string identifiers declared by the rule that is being
    /// currently parsed. The map is filled during the processing of the
    /// strings section of the rule. String identifiers are stored without
    /// the `$` prefix.
    pub(crate) declared_strings: HashMap<&'src str, Ident<'src>>,

    /// Similarly to `declared_strings` this is filled with the identifiers
    /// of the strings declared by the current rule. However, during the
    /// parsing of the rule's condition, identifiers are removed from this
    /// set as they are used in the condition.
    ///
    /// For example, if `$a` appears in the condition, `a` is removed from
    /// this set, if `them` appears, all identifiers are removed because this
    /// keyword refers to all of the identifiers, if a tuple (`$a*`, `$b*`)
    /// appears in the condition, all identifiers starting with `a` and `b`
    /// are removed.
    ///
    /// After the whole condition is parsed, the remaining identifiers are
    /// the unused ones.
    pub(crate) unused_strings: HashSet<&'src str>,

    // TODO: add HashSet named unused_strings and don't remove used
    // identifiers  from declared_strings.
    /// Boolean that indicates if the parser is currently inside the expression
    /// of a `for .. of .. : (<expr>)` statement.
    pub(crate) inside_for_of: bool,

    /// While parsing the string declarations, this holds the identifier
    pub(crate) current_string_identifier: Option<Ident<'src>>,

    /// Used for building error messages and warnings.
    pub(crate) report_builder: ReportBuilder,

    /// Warnings generated during the parsing process.
    pub(crate) warnings: Vec<Warning>,
}

impl<'src> Context<'src> {
    pub(crate) fn new(src: SourceCode<'src>) -> Self {
        let mut report_builder = ReportBuilder::new();
        report_builder.register_source(&src);

        Self {
            src,
            inside_for_of: false,
            declared_strings: HashMap::new(),
            unused_strings: HashSet::new(),
            current_string_identifier: None,
            report_builder,
            warnings: vec![],
        }
    }

    pub(crate) fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.report_builder.with_colors(b);
        self
    }

    /// Returns the identifier of the string that is currently being parsed.
    ///
    /// This function panics if called at some point where a string is not
    /// being parsed, so it should be called only from `string_from_cst`
    /// or any other function under `string_from_cst` in the call tree.
    pub(crate) fn current_string_ident(&self) -> String {
        self.current_string_identifier.as_ref().unwrap().name.to_string()
    }
}

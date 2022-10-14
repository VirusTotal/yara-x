use crate::parser::Ident;
use std::collections::HashMap;

use super::ErrorBuilder;

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

    /// This map contains the string identifiers declared by the rule that
    /// is being currently scanned. The map is filled during the processing
    /// of the strings section of the rule, and it serves for detecting
    /// duplicate identifiers. String identifiers are stored in the map
    /// without the `$` prefix.
    ///
    /// Later, when the rule's condition is processed, string identifiers
    /// are removed from the map as they are referenced by the condition.
    /// For example, if `$a` appears in the condition, `a` is removed from
    /// this map, if `them` appears, all identifiers are removed because this
    /// keyword refers to all of the identifiers, if a tuple (`$a*`, `$b*`)
    /// appears in the condition, all identifiers starting with `a` and `b`
    /// are removed. After the whole condition is processed the remaining
    /// identifiers are the unreferenced ones.
    pub(crate) string_identifiers: HashMap<&'src str, Ident<'src>>,

    /// Boolean that indicates if the parser is currently inside the expression
    /// of a `for .. of .. : (<expr>)` statement.
    pub(crate) inside_for_of: bool,

    /// While parsing the string declarations, this holds the identifier
    pub(crate) current_string_identifier: Option<Ident<'src>>,

    /// Used for building error messages and warnings.
    pub(crate) error_builder: ErrorBuilder,
}

impl<'src> Context<'src> {
    pub(crate) fn new(src: SourceCode<'src>) -> Self {
        let mut error_builder = ErrorBuilder::new();
        error_builder.register_source(&src);

        Self {
            src,
            inside_for_of: false,
            string_identifiers: HashMap::new(),
            current_string_identifier: None,
            error_builder,
        }
    }

    pub(crate) fn colorize_errors(&mut self, b: bool) -> &mut Self {
        self.error_builder.colorize_errors(b);
        self
    }
}

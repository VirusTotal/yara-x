package yara_x

// CompileErrorType identifies a concrete compiler error variant emitted by
// yara_x.
type CompileErrorType string

const (
	CompileErrorTypeArbitraryRegexpPrefix      CompileErrorType = "ArbitraryRegexpPrefix"
	CompileErrorTypeAssignmentMismatch         CompileErrorType = "AssignmentMismatch"
	CompileErrorTypeCircularIncludes           CompileErrorType = "CircularIncludes"
	CompileErrorTypeConflictingRuleIdentifier  CompileErrorType = "ConflictingRuleIdentifier"
	CompileErrorTypeCustomError                CompileErrorType = "CustomError"
	CompileErrorTypeDuplicateModifier          CompileErrorType = "DuplicateModifier"
	CompileErrorTypeDuplicatePattern           CompileErrorType = "DuplicatePattern"
	CompileErrorTypeDuplicateRule              CompileErrorType = "DuplicateRule"
	CompileErrorTypeDuplicateTag               CompileErrorType = "DuplicateTag"
	CompileErrorTypeEmptyPatternSet            CompileErrorType = "EmptyPatternSet"
	CompileErrorTypeEntrypointUnsupported      CompileErrorType = "EntrypointUnsupported"
	CompileErrorTypeIncludeError               CompileErrorType = "IncludeError"
	CompileErrorTypeIncludeNotAllowed          CompileErrorType = "IncludeNotAllowed"
	CompileErrorTypeIncludeNotFound            CompileErrorType = "IncludeNotFound"
	CompileErrorTypeInvalidBase64Alphabet      CompileErrorType = "InvalidBase64Alphabet"
	CompileErrorTypeInvalidEscapeSequence      CompileErrorType = "InvalidEscapeSequence"
	CompileErrorTypeInvalidFloat               CompileErrorType = "InvalidFloat"
	CompileErrorTypeInvalidInteger             CompileErrorType = "InvalidInteger"
	CompileErrorTypeInvalidMetadata            CompileErrorType = "InvalidMetadata"
	CompileErrorTypeInvalidModifier            CompileErrorType = "InvalidModifier"
	CompileErrorTypeInvalidModifierCombination CompileErrorType = "InvalidModifierCombination"
	CompileErrorTypeInvalidPattern             CompileErrorType = "InvalidPattern"
	CompileErrorTypeInvalidRange               CompileErrorType = "InvalidRange"
	CompileErrorTypeInvalidRegexp              CompileErrorType = "InvalidRegexp"
	CompileErrorTypeInvalidRegexpModifier      CompileErrorType = "InvalidRegexpModifier"
	CompileErrorTypeInvalidRuleName            CompileErrorType = "InvalidRuleName"
	CompileErrorTypeInvalidTag                 CompileErrorType = "InvalidTag"
	CompileErrorTypeInvalidUTF8                CompileErrorType = "InvalidUTF8"
	CompileErrorTypeMethodNotAllowedInWith     CompileErrorType = "MethodNotAllowedInWith"
	CompileErrorTypeMismatchingTypes           CompileErrorType = "MismatchingTypes"
	CompileErrorTypeMissingMetadata            CompileErrorType = "MissingMetadata"
	CompileErrorTypeMixedGreediness            CompileErrorType = "MixedGreediness"
	CompileErrorTypeNumberOutOfRange           CompileErrorType = "NumberOutOfRange"
	CompileErrorTypePotentiallySlowLoop        CompileErrorType = "PotentiallySlowLoop"
	CompileErrorTypeSlowPattern                CompileErrorType = "SlowPattern"
	CompileErrorTypeSyntaxError                CompileErrorType = "SyntaxError"
	CompileErrorTypeTooManyPatterns            CompileErrorType = "TooManyPatterns"
	CompileErrorTypeUnexpectedEscapeSequence   CompileErrorType = "UnexpectedEscapeSequence"
	CompileErrorTypeUnexpectedNegativeNumber   CompileErrorType = "UnexpectedNegativeNumber"
	CompileErrorTypeUnknownField               CompileErrorType = "UnknownField"
	CompileErrorTypeUnknownIdentifier          CompileErrorType = "UnknownIdentifier"
	CompileErrorTypeUnknownModule              CompileErrorType = "UnknownModule"
	CompileErrorTypeUnknownPattern             CompileErrorType = "UnknownPattern"
	CompileErrorTypeUnknownTag                 CompileErrorType = "UnknownTag"
	CompileErrorTypeUnusedPattern              CompileErrorType = "UnusedPattern"
	CompileErrorTypeWrongArguments             CompileErrorType = "WrongArguments"
	CompileErrorTypeWrongType                  CompileErrorType = "WrongType"
)

// CompileErrorCode identifies a compiler error code emitted by yara_x.
type CompileErrorCode string

const (
	CompileErrorCodeArbitraryRegexpPrefix      CompileErrorCode = "E045"
	CompileErrorCodeAssignmentMismatch         CompileErrorCode = "E005"
	CompileErrorCodeCircularIncludes           CompileErrorCode = "E046"
	CompileErrorCodeConflictingRuleIdentifier  CompileErrorCode = "E013"
	CompileErrorCodeCustomError                CompileErrorCode = "E100"
	CompileErrorCodeDuplicateModifier          CompileErrorCode = "E020"
	CompileErrorCodeDuplicatePattern           CompileErrorCode = "E023"
	CompileErrorCodeDuplicateRule              CompileErrorCode = "E012"
	CompileErrorCodeDuplicateTag               CompileErrorCode = "E021"
	CompileErrorCodeEmptyPatternSet            CompileErrorCode = "E016"
	CompileErrorCodeEntrypointUnsupported      CompileErrorCode = "E017"
	CompileErrorCodeIncludeError               CompileErrorCode = "E042"
	CompileErrorCodeIncludeNotAllowed          CompileErrorCode = "E044"
	CompileErrorCodeIncludeNotFound            CompileErrorCode = "E043"
	CompileErrorCodeInvalidBase64Alphabet      CompileErrorCode = "E026"
	CompileErrorCodeInvalidEscapeSequence      CompileErrorCode = "E029"
	CompileErrorCodeInvalidFloat               CompileErrorCode = "E028"
	CompileErrorCodeInvalidInteger             CompileErrorCode = "E027"
	CompileErrorCodeInvalidMetadata            CompileErrorCode = "E037"
	CompileErrorCodeInvalidModifier            CompileErrorCode = "E033"
	CompileErrorCodeInvalidModifierCombination CompileErrorCode = "E019"
	CompileErrorCodeInvalidPattern             CompileErrorCode = "E024"
	CompileErrorCodeInvalidRange               CompileErrorCode = "E011"
	CompileErrorCodeInvalidRegexp              CompileErrorCode = "E014"
	CompileErrorCodeInvalidRegexpModifier      CompileErrorCode = "E030"
	CompileErrorCodeInvalidRuleName            CompileErrorCode = "E039"
	CompileErrorCodeInvalidTag                 CompileErrorCode = "E041"
	CompileErrorCodeInvalidUTF8                CompileErrorCode = "E032"
	CompileErrorCodeMethodNotAllowedInWith     CompileErrorCode = "E036"
	CompileErrorCodeMismatchingTypes           CompileErrorCode = "E003"
	CompileErrorCodeMissingMetadata            CompileErrorCode = "E038"
	CompileErrorCodeMixedGreediness            CompileErrorCode = "E015"
	CompileErrorCodeNumberOutOfRange           CompileErrorCode = "E007"
	CompileErrorCodePotentiallySlowLoop        CompileErrorCode = "E034"
	CompileErrorCodeSlowPattern                CompileErrorCode = "E018"
	CompileErrorCodeSyntaxError                CompileErrorCode = "E001"
	CompileErrorCodeTooManyPatterns            CompileErrorCode = "E035"
	CompileErrorCodeUnexpectedEscapeSequence   CompileErrorCode = "E031"
	CompileErrorCodeUnexpectedNegativeNumber   CompileErrorCode = "E006"
	CompileErrorCodeUnknownField               CompileErrorCode = "E008"
	CompileErrorCodeUnknownIdentifier          CompileErrorCode = "E009"
	CompileErrorCodeUnknownModule              CompileErrorCode = "E010"
	CompileErrorCodeUnknownPattern             CompileErrorCode = "E025"
	CompileErrorCodeUnknownTag                 CompileErrorCode = "E040"
	CompileErrorCodeUnusedPattern              CompileErrorCode = "E022"
	CompileErrorCodeWrongArguments             CompileErrorCode = "E004"
	CompileErrorCodeWrongType                  CompileErrorCode = "E002"
)

// WarningType identifies a concrete compiler warning variant emitted by
// yara_x.
type WarningType string

const (
	WarningTypeAmbiguousExpression                WarningType = "AmbiguousExpression"
	WarningTypeBooleanIntegerComparison           WarningType = "BooleanIntegerComparison"
	WarningTypeConsecutiveJumps                   WarningType = "ConsecutiveJumps"
	WarningTypeDeprecatedField                    WarningType = "DeprecatedField"
	WarningTypeDuplicateImport                    WarningType = "DuplicateImport"
	WarningTypeGlobalRuleMisuse                   WarningType = "GlobalRuleMisuse"
	WarningTypeIgnoredModule                      WarningType = "IgnoredModule"
	WarningTypeIgnoredRule                        WarningType = "IgnoredRule"
	WarningTypeInvalidMetadata                    WarningType = "InvalidMetadata"
	WarningTypeInvalidRuleName                    WarningType = "InvalidRuleName"
	WarningTypeInvalidTag                         WarningType = "InvalidTag"
	WarningTypeInvariantBooleanExpression         WarningType = "InvariantBooleanExpression"
	WarningTypeMissingMetadata                    WarningType = "MissingMetadata"
	WarningTypeNonBooleanAsBoolean                WarningType = "NonBooleanAsBoolean"
	WarningTypePotentiallySlowLoop                WarningType = "PotentiallySlowLoop"
	WarningTypePotentiallyUnsatisfiableExpression WarningType = "PotentiallyUnsatisfiableExpression"
	WarningTypeRedundantCaseModifier              WarningType = "RedundantCaseModifier"
	WarningTypeSlowPattern                        WarningType = "SlowPattern"
	WarningTypeTextPatternAsHex                   WarningType = "TextPatternAsHex"
	WarningTypeTooManyIterations                  WarningType = "TooManyIterations"
	WarningTypeUnknownTag                         WarningType = "UnknownTag"
	WarningTypeUnsatisfiableExpression            WarningType = "UnsatisfiableExpression"
	WarningTypeUnusedIdentifier                   WarningType = "UnusedIdentifier"
)

// WarningCode identifies a compiler warning code emitted by yara_x.
type WarningCode string

const (
	WarningCodeAmbiguousExpression                WarningCode = "ambiguous_expr"
	WarningCodeBooleanIntegerComparison           WarningCode = "bool_int_comparison"
	WarningCodeConsecutiveJumps                   WarningCode = "consecutive_jumps"
	WarningCodeDeprecatedField                    WarningCode = "deprecated_field"
	WarningCodeDuplicateImport                    WarningCode = "duplicate_import"
	WarningCodeGlobalRuleMisuse                   WarningCode = "global_rule_misuse"
	WarningCodeIgnoredModule                      WarningCode = "unsupported_module"
	WarningCodeIgnoredRule                        WarningCode = "ignored_rule"
	WarningCodeInvalidMetadata                    WarningCode = "invalid_metadata"
	WarningCodeInvalidRuleName                    WarningCode = "invalid_rule_name"
	WarningCodeInvalidTag                         WarningCode = "invalid_tag"
	WarningCodeInvariantBooleanExpression         WarningCode = "invariant_expr"
	WarningCodeMissingMetadata                    WarningCode = "missing_metadata"
	WarningCodeNonBooleanAsBoolean                WarningCode = "non_bool_expr"
	WarningCodePotentiallySlowLoop                WarningCode = "potentially_slow_loop"
	WarningCodePotentiallyUnsatisfiableExpression WarningCode = "unsatisfiable_expr"
	WarningCodeRedundantCaseModifier              WarningCode = "redundant_modifier"
	WarningCodeSlowPattern                        WarningCode = "slow_pattern"
	WarningCodeTextPatternAsHex                   WarningCode = "text_as_hex"
	WarningCodeTooManyIterations                  WarningCode = "too_many_iterations"
	WarningCodeUnknownTag                         WarningCode = "unknown_tag"
	WarningCodeUnsatisfiableExpression            WarningCode = "unsatisfiable_expr"
	WarningCodeUnusedIdentifier                   WarningCode = "unused_identifier"
)

// CodeID returns the compiler error code as a typed identifier.
func (c CompileError) CodeID() CompileErrorCode {
	return CompileErrorCode(c.Code)
}

// HasType reports whether the compiler error is the requested concrete type.
func (c CompileError) HasType(t CompileErrorType) bool {
	return c.Type == t
}

// HasCode reports whether the compiler error uses the requested code.
func (c CompileError) HasCode(code CompileErrorCode) bool {
	return c.CodeID() == code
}

// Is lets callers match compiler errors with errors.Is using any subset of
// Type, Code, or Title, for example:
// errors.Is(err, &CompileError{Type: CompileErrorTypeUnknownIdentifier}).
func (c CompileError) Is(target error) bool {
	switch t := target.(type) {
	case *CompileError:
		if t == nil {
			return false
		}
		return c.matches(*t)
	case CompileError:
		return c.matches(t)
	default:
		return false
	}
}

func (c CompileError) matches(target CompileError) bool {
	if target.Type == "" && target.Code == "" && target.Title == "" {
		return false
	}
	if target.Type != "" && c.Type != target.Type {
		return false
	}
	if target.Code != "" && c.Code != target.Code {
		return false
	}
	if target.Title != "" && c.Title != target.Title {
		return false
	}
	return true
}

// CodeID returns the warning code as a typed identifier.
func (w Warning) CodeID() WarningCode {
	return WarningCode(w.Code)
}

// HasType reports whether the warning is the requested concrete type.
func (w Warning) HasType(t WarningType) bool {
	return w.Type == t
}

// HasCode reports whether the warning uses the requested code.
func (w Warning) HasCode(code WarningCode) bool {
	return w.CodeID() == code
}

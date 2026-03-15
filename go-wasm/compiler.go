package yara_x

import (
	"encoding/json"
	"fmt"
	"math"
	"runtime"
)

// A CompileOption represents an option passed to [NewCompiler] and [Compile].
type CompileOption func(c *Compiler) error

// The Globals option for [NewCompiler] and [Compile] allows you to define
// global variables.
func Globals(vars map[string]interface{}) CompileOption {
	return func(c *Compiler) error {
		for ident, value := range vars {
			c.vars[ident] = value
		}
		return nil
	}
}

// IgnoreModule is an option for [NewCompiler] and [Compile] that allows
// ignoring a given module.
func IgnoreModule(module string) CompileOption {
	return func(c *Compiler) error {
		c.ignoredModules[module] = true
		return nil
	}
}

// WithFeature enables a feature while compiling rules.
//
// NOTE: This API is still experimental and subject to change.
func WithFeature(feature string) CompileOption {
	return func(c *Compiler) error {
		c.features = append(c.features, feature)
		return nil
	}
}

// BanModule is an option for [NewCompiler] and [Compile] that allows
// banning the use of a given module.
func BanModule(module string, errTitle string, errMessage string) CompileOption {
	return func(c *Compiler) error {
		c.bannedModules[module] = bannedModule{errTitle, errMessage}
		return nil
	}
}

// RelaxedReSyntax is an option for [NewCompiler] and [Compile] that
// determines whether the compiler should adopt a more relaxed approach
// while parsing regular expressions.
func RelaxedReSyntax(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.relaxedReSyntax = yes
		return nil
	}
}

// ConditionOptimization is an option for [NewCompiler] and [Compile] that
// enables the optimization of rule conditions.
func ConditionOptimization(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.conditionOptimization = yes
		return nil
	}
}

// ErrorOnSlowPattern is an option for [NewCompiler] and [Compile] that
// tells the compiler to treat slow patterns as errors instead of warnings.
func ErrorOnSlowPattern(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.errorOnSlowPattern = yes
		return nil
	}
}

// ErrorOnSlowLoop is an option for [NewCompiler] and [Compile] that
// tells the compiler to treat slow loops as errors instead of warnings.
func ErrorOnSlowLoop(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.errorOnSlowLoop = yes
		return nil
	}
}

// EnableIncludes allows the compiler to process include directives in YARA
// rules.
func EnableIncludes(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.includesEnabled = yes
		return nil
	}
}

// IncludeDir is an option for [NewCompiler] and [Compile] that tells the
// compiler where to look for included files.
func IncludeDir(path string) CompileOption {
	return func(c *Compiler) error {
		c.includeDirs = append(c.includeDirs, path)
		return nil
	}
}

// RuleNameLinter adds a linter that enforces a rule-name regular expression.
func RuleNameLinter(regex string, errOnFail bool) CompileOption {
	return func(c *Compiler) error {
		c.linters = append(c.linters, compilerLinterSpec{
			kind:      compilerLinterRuleName,
			str:       regex,
			errOnFail: errOnFail,
		})
		return nil
	}
}

// TagsAllowedLinter adds a linter that restricts tags to the provided list.
func TagsAllowedLinter(tags []string, errOnFail bool) CompileOption {
	return func(c *Compiler) error {
		c.linters = append(c.linters, compilerLinterSpec{
			kind:      compilerLinterTagsAllowed,
			list:      append([]string(nil), tags...),
			errOnFail: errOnFail,
		})
		return nil
	}
}

// TagRegexLinter adds a linter that enforces a tag regular expression.
func TagRegexLinter(regex string, errOnFail bool) CompileOption {
	return func(c *Compiler) error {
		c.linters = append(c.linters, compilerLinterSpec{
			kind:      compilerLinterTagRegex,
			str:       regex,
			errOnFail: errOnFail,
		})
		return nil
	}
}

// RequiredMetadataLinter adds a linter that requires metadata in every rule.
func RequiredMetadataLinter(identifier string, errOnFail bool) CompileOption {
	return func(c *Compiler) error {
		c.linters = append(c.linters, compilerLinterSpec{
			kind:      compilerLinterRequiredMetadata,
			str:       identifier,
			errOnFail: errOnFail,
		})
		return nil
	}
}

// A structure that contains the options passed to [Compiler.AddSource].
type sourceOptions struct {
	origin string
}

// A SourceOption represents an option passed to [Compiler.AddSource].
type SourceOption func(opt *sourceOptions) error

// WithOrigin is an option for [Compiler.AddSource] that specifies the
// origin of the source code.
func WithOrigin(origin string) SourceOption {
	return func(opts *sourceOptions) error {
		opts.origin = origin
		return nil
	}
}

// CompileError represents each of the errors returned by [Compiler.Errors].
type CompileError struct {
	Type    CompileErrorType `json:"type"`
	Code    string           `json:"code"`
	Title   string           `json:"title"`
	Line    int              `json:"line"`
	Column  int              `json:"column"`
	Labels  []Label          `json:"labels,omitempty"`
	Footers []Footer         `json:"footers,omitempty"`
	Text    string           `json:"text"`
}

// Warning represents each of the warnings returned by [Compiler.Warnings].
type Warning struct {
	Type    WarningType `json:"type"`
	Code    string      `json:"code"`
	Title   string      `json:"title"`
	Line    int         `json:"line"`
	Column  int         `json:"column"`
	Labels  []Label     `json:"labels,omitempty"`
	Footers []Footer    `json:"footers,omitempty"`
	Text    string      `json:"text"`
}

// Label represents a label in a [CompileError].
type Label struct {
	Level      string `json:"level"`
	CodeOrigin string `json:"code_origin"`
	Line       int64  `json:"line"`
	Column     int64  `json:"column"`
	Span       Span   `json:"span"`
	Text       string `json:"text"`
}

// Footer represents a footer in a [CompileError].
type Footer struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Span represents the starting and ending point of some piece of source code.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Error returns the error's full report.
func (c CompileError) Error() string {
	return c.Text
}

type bannedModule struct {
	errTitle string
	errMsg   string
}

type compilerLinterKind uint8

const (
	compilerLinterRuleName compilerLinterKind = iota
	compilerLinterTagsAllowed
	compilerLinterTagRegex
	compilerLinterRequiredMetadata
)

type compilerLinterSpec struct {
	kind      compilerLinterKind
	str       string
	list      []string
	errOnFail bool
}

// Compiler represents a YARA compiler.
type Compiler struct {
	client                *guestClient
	handle                uint32
	relaxedReSyntax       bool
	conditionOptimization bool
	errorOnSlowPattern    bool
	errorOnSlowLoop       bool
	includesEnabled       bool
	ignoredModules        map[string]bool
	bannedModules         map[string]bannedModule
	vars                  map[string]interface{}
	features              []string
	includeDirs           []string
	linters               []compilerLinterSpec
}

// NewCompiler creates a new compiler.
func NewCompiler(opts ...CompileOption) (*Compiler, error) {
	c := &Compiler{
		includesEnabled: true,
		ignoredModules:  make(map[string]bool),
		bannedModules:   make(map[string]bannedModule),
		vars:            make(map[string]interface{}),
		features:        make([]string, 0),
		includeDirs:     make([]string, 0),
		linters:         make([]compilerLinterSpec, 0),
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	flags := uint32(0)
	if c.relaxedReSyntax {
		flags |= 2 // YRX_RELAXED_RE_SYNTAX
	}
	if c.conditionOptimization {
		flags |= 16 // YRX_ENABLE_CONDITION_OPTIMIZATION
	}
	if c.errorOnSlowPattern {
		flags |= 4 // YRX_ERROR_ON_SLOW_PATTERN
	}
	if c.errorOnSlowLoop {
		flags |= 8 // YRX_ERROR_ON_SLOW_LOOP
	}
	if !c.includesEnabled {
		flags |= 32 // YRX_DISABLE_INCLUDES
	}

	client, err := newGuestClient()
	if err != nil {
		return nil, err
	}

	handle, err := client.callHandle(
		"go_yrx_compiler_create",
		uint64(flags),
	)
	if err != nil {
		client.close()
		return nil, err
	}

	c.client = client
	c.handle = handle

	if err := c.initialize(); err != nil {
		c.Destroy()
		return nil, err
	}

	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c, nil
}

func (c *Compiler) initialize() error {
	for name := range c.ignoredModules {
		if err := c.ignoreModule(name); err != nil {
			return err
		}
	}
	for _, feature := range c.features {
		if err := c.enableFeature(feature); err != nil {
			return err
		}
	}
	for name, v := range c.bannedModules {
		if err := c.banModule(name, v.errTitle, v.errMsg); err != nil {
			return err
		}
	}
	for ident, value := range c.vars {
		if err := c.DefineGlobal(ident, value); err != nil {
			return err
		}
	}
	for _, dir := range c.includeDirs {
		if err := c.addIncludeDir(dir); err != nil {
			return err
		}
	}
	for _, linter := range c.linters {
		if err := c.applyLinter(linter); err != nil {
			return err
		}
	}
	return nil
}

func (c *Compiler) withStringArg(value string, fn func(ptr, size uint32) error) error {
	ptr, length, err := c.client.writeString(value)
	if err != nil {
		return err
	}
	defer c.client.free(ptr, length, 1)
	return fn(ptr, length)
}

// AddSource adds YARA source code to be compiled.
func (c *Compiler) AddSource(src string, opts ...SourceOption) error {
	options := &sourceOptions{}
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return err
		}
	}

	srcPtr, srcLen, err := c.client.writeString(src)
	if err != nil {
		return err
	}
	defer c.client.free(srcPtr, srcLen, 1)

	var originPtr uint32
	var originLen uint32
	if options.origin != "" {
		originPtr, originLen, err = c.client.writeString(options.origin)
		if err != nil {
			return err
		}
		defer c.client.free(originPtr, originLen, 1)
	}

	return c.client.callStatus(
		"go_yrx_compiler_add_source_with_origin",
		uint64(c.handle),
		uint64(srcPtr),
		uint64(srcLen),
		uint64(originPtr),
		uint64(originLen),
	)
}

// addIncludeDir adds an include directory to the compiler.
func (c *Compiler) addIncludeDir(dir string) error {
	return c.withStringArg(dir, func(ptr, size uint32) error {
		return c.client.callStatus(
			"go_yrx_compiler_add_include_dir",
			uint64(c.handle),
			uint64(ptr),
			uint64(size),
		)
	})
}

// enableFeature enables a compiler feature.
func (c *Compiler) enableFeature(feature string) error {
	return c.withStringArg(feature, func(ptr, size uint32) error {
		return c.client.callStatus(
			"go_yrx_compiler_enable_feature",
			uint64(c.handle),
			uint64(ptr),
			uint64(size),
		)
	})
}

// ignoreModule tells the compiler to ignore the module with the given name.
func (c *Compiler) ignoreModule(module string) error {
	return c.withStringArg(module, func(ptr, size uint32) error {
		return c.client.callStatus(
			"go_yrx_compiler_ignore_module",
			uint64(c.handle),
			uint64(ptr),
			uint64(size),
		)
	})
}

func (c *Compiler) banModule(module, errorTitle, errorMessage string) error {
	modulePtr, moduleLen, err := c.client.writeString(module)
	if err != nil {
		return err
	}
	defer c.client.free(modulePtr, moduleLen, 1)

	titlePtr, titleLen, err := c.client.writeString(errorTitle)
	if err != nil {
		return err
	}
	defer c.client.free(titlePtr, titleLen, 1)

	messagePtr, messageLen, err := c.client.writeString(errorMessage)
	if err != nil {
		return err
	}
	defer c.client.free(messagePtr, messageLen, 1)

	return c.client.callStatus(
		"go_yrx_compiler_ban_module",
		uint64(c.handle),
		uint64(modulePtr),
		uint64(moduleLen),
		uint64(titlePtr),
		uint64(titleLen),
		uint64(messagePtr),
		uint64(messageLen),
	)
}

func (c *Compiler) applyLinter(linter compilerLinterSpec) error {
	switch linter.kind {
	case compilerLinterRuleName:
		return c.withStringArg(linter.str, func(ptr, size uint32) error {
			var errFlag uint64
			if linter.errOnFail {
				errFlag = 1
			}
			return c.client.callStatus(
				"go_yrx_compiler_add_linter_rule_name",
				uint64(c.handle),
				uint64(ptr),
				uint64(size),
				errFlag,
			)
		})
	case compilerLinterTagsAllowed:
		payload, err := json.Marshal(linter.list)
		if err != nil {
			return err
		}
		ptr, length, err := c.client.allocAndWrite(payload, 1)
		if err != nil {
			return err
		}
		defer c.client.free(ptr, length, 1)
		var errFlag uint64
		if linter.errOnFail {
			errFlag = 1
		}
		return c.client.callStatus(
			"go_yrx_compiler_add_linter_tags_allowed",
			uint64(c.handle),
			uint64(ptr),
			uint64(length),
			errFlag,
		)
	case compilerLinterTagRegex:
		return c.withStringArg(linter.str, func(ptr, size uint32) error {
			var errFlag uint64
			if linter.errOnFail {
				errFlag = 1
			}
			return c.client.callStatus(
				"go_yrx_compiler_add_linter_tag_regex",
				uint64(c.handle),
				uint64(ptr),
				uint64(size),
				errFlag,
			)
		})
	case compilerLinterRequiredMetadata:
		return c.withStringArg(linter.str, func(ptr, size uint32) error {
			var errFlag uint64
			if linter.errOnFail {
				errFlag = 1
			}
			return c.client.callStatus(
				"go_yrx_compiler_add_linter_required_metadata",
				uint64(c.handle),
				uint64(ptr),
				uint64(size),
				errFlag,
			)
		})
	default:
		return fmt.Errorf("unsupported compiler linter kind %d", linter.kind)
	}
}

func (c *Compiler) addLinter(linter compilerLinterSpec) error {
	if err := c.applyLinter(linter); err != nil {
		return err
	}
	if linter.list != nil {
		linter.list = append([]string(nil), linter.list...)
	}
	c.linters = append(c.linters, linter)
	return nil
}

// AddRuleNameLinter makes rule names match the given regular expression.
func (c *Compiler) AddRuleNameLinter(regex string, errOnFail bool) error {
	return c.addLinter(compilerLinterSpec{
		kind:      compilerLinterRuleName,
		str:       regex,
		errOnFail: errOnFail,
	})
}

// AddTagsAllowedLinter restricts rule tags to the provided allowed list.
func (c *Compiler) AddTagsAllowedLinter(tags []string, errOnFail bool) error {
	return c.addLinter(compilerLinterSpec{
		kind:      compilerLinterTagsAllowed,
		list:      tags,
		errOnFail: errOnFail,
	})
}

// AddTagRegexLinter makes every rule tag match the given regular expression.
func (c *Compiler) AddTagRegexLinter(regex string, errOnFail bool) error {
	return c.addLinter(compilerLinterSpec{
		kind:      compilerLinterTagRegex,
		str:       regex,
		errOnFail: errOnFail,
	})
}

// AddRequiredMetadataLinter requires every rule to contain the given metadata.
func (c *Compiler) AddRequiredMetadataLinter(identifier string, errOnFail bool) error {
	return c.addLinter(compilerLinterSpec{
		kind:      compilerLinterRequiredMetadata,
		str:       identifier,
		errOnFail: errOnFail,
	})
}

// NewNamespace creates a new namespace for subsequently added sources.
func (c *Compiler) NewNamespace(namespace string) {
	err := c.withStringArg(namespace, func(ptr, size uint32) error {
		return c.client.callStatus(
			"go_yrx_compiler_new_namespace",
			uint64(c.handle),
			uint64(ptr),
			uint64(size),
		)
	})
	if err != nil {
		panic(err)
	}
}

// DefineGlobal defines a global variable and sets its initial value.
func (c *Compiler) DefineGlobal(ident string, value interface{}) error {
	identPtr, identLen, err := c.client.writeString(ident)
	if err != nil {
		return err
	}
	defer c.client.free(identPtr, identLen, 1)

	switch v := value.(type) {
	case int:
		err = c.client.callStatus("go_yrx_compiler_define_global_int", uint64(c.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(int64(v)))
	case int32:
		err = c.client.callStatus("go_yrx_compiler_define_global_int", uint64(c.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(int64(v)))
	case int64:
		err = c.client.callStatus("go_yrx_compiler_define_global_int", uint64(c.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(v))
	case bool:
		var b uint64
		if v {
			b = 1
		}
		err = c.client.callStatus("go_yrx_compiler_define_global_bool", uint64(c.handle), uint64(identPtr), uint64(identLen), b)
	case string:
		valuePtr, valueLen, allocErr := c.client.writeString(v)
		if allocErr != nil {
			return allocErr
		}
		defer c.client.free(valuePtr, valueLen, 1)
		err = c.client.callStatus("go_yrx_compiler_define_global_str", uint64(c.handle), uint64(identPtr), uint64(identLen), uint64(valuePtr), uint64(valueLen))
	case float32:
		err = c.client.callStatus("go_yrx_compiler_define_global_float", uint64(c.handle), uint64(identPtr), uint64(identLen), math.Float64bits(float64(v)))
	case float64:
		err = c.client.callStatus("go_yrx_compiler_define_global_float", uint64(c.handle), uint64(identPtr), uint64(identLen), math.Float64bits(v))
	case map[string]interface{}, []interface{}:
		jsonBytes, marshalErr := json.Marshal(v)
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal %q to json: %w", ident, marshalErr)
		}
		valuePtr, valueLen, allocErr := c.client.allocAndWrite(jsonBytes, 1)
		if allocErr != nil {
			return allocErr
		}
		defer c.client.free(valuePtr, valueLen, 1)
		err = c.client.callStatus("go_yrx_compiler_define_global_json", uint64(c.handle), uint64(identPtr), uint64(identLen), uint64(valuePtr), uint64(valueLen))
	default:
		return fmt.Errorf("variable `%s` has unsupported type: %T", ident, v)
	}

	return err
}

// Errors returns the errors that occurred during compilation across multiple
// calls to [Compiler.AddSource].
func (c *Compiler) Errors() []CompileError {
	bufHandle, err := c.client.callHandle("go_yrx_compiler_errors_json", uint64(c.handle))
	if err != nil {
		panic(err)
	}

	var result []CompileError
	if err := c.client.withBufferView(bufHandle, func(payload []byte) error {
		return unmarshalWireJSON(payload, (*compileErrorList)(&result))
	}); err != nil {
		panic(err)
	}
	return result
}

// Warnings returns the warnings that occurred during compilation across
// multiple calls to [Compiler.AddSource].
func (c *Compiler) Warnings() []Warning {
	bufHandle, err := c.client.callHandle("go_yrx_compiler_warnings_json", uint64(c.handle))
	if err != nil {
		panic(err)
	}

	var result []Warning
	if err := c.client.withBufferView(bufHandle, func(payload []byte) error {
		return unmarshalWireJSON(payload, (*warningList)(&result))
	}); err != nil {
		panic(err)
	}
	return result
}

// EmitWasmFile writes the compiler-generated WASM module to the given path.
//
// Like [Compiler.Build], this consumes the currently added sources and resets
// the compiler so it can be reused.
func (c *Compiler) EmitWasmFile(path string) error {
	pathPtr, pathLen, err := c.client.writeString(path)
	if err != nil {
		return err
	}
	defer c.client.free(pathPtr, pathLen, 1)

	if err := c.client.callStatus(
		"go_yrx_compiler_emit_wasm_file",
		uint64(c.handle),
		uint64(pathPtr),
		uint64(pathLen),
	); err != nil {
		return err
	}

	return c.initialize()
}

// Build creates a [Rules] object containing a compiled version of all the
// YARA rules previously added to the compiler.
func (c *Compiler) Build() *Rules {
	tmpRulesHandle, err := c.client.callHandle("go_yrx_compiler_build", uint64(c.handle))
	if err != nil {
		panic(err)
	}
	defer func() {
		_, _ = c.client.call("go_yrx_rules_destroy", uint64(tmpRulesHandle))
	}()

	serialized, err := readRulesBuffer(c.client, "go_yrx_rules_serialize", tmpRulesHandle)
	if err != nil {
		panic(err)
	}

	rules, err := newPortableRules(c.client, tmpRulesHandle, serialized)
	if err != nil {
		panic(err)
	}

	if err := c.initialize(); err != nil {
		panic(err)
	}

	runtime.SetFinalizer(rules, (*Rules).Destroy)
	return rules
}

// Destroy destroys the compiler.
func (c *Compiler) Destroy() {
	if c == nil {
		return
	}
	if c.client != nil && c.handle != 0 {
		_, _ = c.client.call("go_yrx_compiler_destroy", uint64(c.handle))
		c.handle = 0
	}
	if c.client != nil {
		c.client.close()
	}
	c.client = nil
	runtime.SetFinalizer(c, nil)
}

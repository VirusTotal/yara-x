---
title: "C/C++"
description: ""
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "c-api"
weight: 510
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

C and C++ are still among the most popular languages for systems programming
and, the *lingua franca* for interoperability between languages. Without the
possibility of talking to C/C++ code, YARA-X would never get serious adoption.
For this reason, we provide a C API that allows interacting with YARA-X from
C/C++ programs.

This section describes the C API and explains how to create the header files
and libraries that you will need to integrate YARA-X in your project.

## Building the C library

For building the C library using [`cargo-c`](https://github.com/lu-zero/cargo-c)
is the easiest way. If you don't have `cargo-c` installed yet, this is the first
step:

```shell
cargo install cargo-c
```

Once `cargo-c` in installed, go to the root directory of the YARA-X repository
and type:

```shell
cargo cinstall -p yara-x-capi --release
```

The command above will put the library and header files in the correct path
in your system (usually `/usr/local/lib` and `/usr/local/include` for Linux
and MacOS users), and will generate a `.pc` file so that `pkg-config` knows
about the library.

In Linux and MacOS you can check if everything went fine by compiling a simple
test program, like this:

```shell
cat <<EOF > test.c
#include <yara_x.h>
int main() {
    YRX_RULES* rules;
    yrx_compile("rule dummy { condition: true }", &rules);
    yrx_rules_destroy(rules);
}
EOF

gcc `pkg-config --cflags yara_x_capi` `pkg-config --libs yara_x_capi` test.c
```

The compilation should succeed without errors.

Windows users will find all the files needed for importing YARA-X in the
`target/x86_64-pc-windows-msvc/release` directory. This includes:

* A header file `yara_x.h`
* A [module definition file](https://learn.microsoft.com/en-us/cpp/build/reference/module-definition-dot-def-files) `yara_x_capi.def`
* A DLL file `yara_x_capi.dll` with its corresponding import
  library `yara_x_capi.dll.lib`
* A static library `yara_x_capi.lib`

## API overview

Using YARA-X from C involves a two-step process: rule compilation and scanning.
During the rule compilation phase you transform YARA rules from text
into a compiled [YRX_RULES](#yrx_rules) object. This object is later used for
scanning data.

To compile rules, you can either use the [yrx_compile](#yrx_compile)
function or a [YRX_COMPILER](#yrx_compiler) object. The former is simpler and
sufficient for simpler scenarios. For more complex use-cases involving the use
of namespaces and multiple rule sets, the latter method is necessary.

Once you have a [YRX_RULES](#yrx_rules) object, you must create
a [YRX_SCANNER](#yrx_scanner) object that will use the compiled rules for
scanning data. A new scanner can be created
with [yrx_scanner_create](#yrx_scanner_create). It's ok to use the
same [YRX_RULES](#yrx_rules) object with multiple scanners, and use each scanner
from a different thread to scan different data with the same rules in parallel.
Each scanner must be used by a single thread, though.

Scanners and rules must be destroyed by
calling [yrx_scanner_destroy](#yrx_scanner_destroy)
and [yrx_rules_destroy](#yrx_rules_destroy) respectively, but the rules must
be destroyed only after all scanners using them are already destroyed.

You must use [yrx_scanner_on_matching_rule](#yrx_scanner_on_matching_rule) to
give the scanner a callback function that will be called for every matching
rule. The callback function receives a pointer to a [YRX_RULE](#yrx_rule)
structure representing the matching rule, and gives you access to details
about the rule, like its identifier and namespace.

## API reference

### yrx_compile

```c
enum YRX_RESULT yrx_compile(
    const char *src, 
    struct YRX_RULES **rules);
```

Function that takes a string with one or more YARA rules and produces
a [YRX_RULES](#yrx_rules) object representing the rules in compiled form. This
is the simplest way for compiling YARA rules, for more advanced use-cases you
must use a [YRX_COMPILER](#yrx_compiler).

------

### yrx_last_error

```c
const char *yrx_last_error(void);
```

Returns the error message corresponding to the most recent invocation of a
function in this API by the current thread. The returned pointer will be `null`
if the most recent function call by the current thread was successfully.

Also, the pointer is only valid until the current thread calls some other
function in this API.

------

### YRX_COMPILER

Type that represents a YARA-X compiler. It takes one or more sets of YARA
rules in text form and compile them into a [YRX_RULES](#yrx_rules) object.

#### yrx_compiler_create

```c
enum YRX_RESULT yrx_compiler_create(
    uint32_t flags,
    struct YRX_COMPILER **compiler);
```

Creates a new compiler. It must be destroyed
with [yrx_compiler_destroy](#yrx_compiler_destroy). The `flags` argument can be
0, or any
combination of the following flags:

* `YRX_COLORIZE_ERRORS`

  Add colors to error messages.

* `YRX_RELAXED_RE_SYNTAX`

  YARA-X enforces stricter regular expression syntax compared to YARA.
  For instance, YARA accepts invalid escape sequences and treats them
  as literal characters (e.g., \R is interpreted as a literal 'R'). It
  also allows some special characters to appear unescaped, inferring
  their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
  literal, but in `/foo{0,1}bar/` they form the repetition operator
  `{0,1}`).

  When this flag is set, YARA-X mimics YARA's behavior, allowing
  constructs that YARA-X doesn't accept by default.

* `YRX_ERROR_ON_SLOW_PATTERN`

  Treats slow patterns as errors instead of warnings.

* `YRX_ERROR_ON_SLOW_LOOP`

  Treats slow loops as errors instead of warnings.

* `YRX_ENABLE_CONDITION_OPTIMIZATION`

  Enables optimizations for rule conditions. This includes techniques
  like common subexpression elimination (CSE) and loop-invariant
  code motion (LICM).

* `YRX_DISABLE_INCLUDES`

  Disables `include` statements. The compiler will produce an error
  if an `include` statement is encountered.

#### yrx_compiler_destroy

```c
void yrx_compiler_destroy(
    struct YRX_COMPILER *compiler);
```

Destroys the compiler [YRX_COMPILER](#yrx_compiler) object.

#### yrx_compiler_add_source

```c
enum YRX_RESULT yrx_compiler_add_source(
    struct YRX_COMPILER *compiler, 
    const char *src);
```

Adds a YARA source code to be compiled. This function can be called multiple
times.

#### yrx_compiler_add_source_with_origin

```c
enum YRX_RESULT yrx_compiler_add_source_with_origin(
    struct YRX_COMPILER *compiler,
    const char *src,
    const char *origin);
```

Adds a YARA source code to be compiled, specifying an origin for the source
code. This function is similar to [yrx_compiler_add_source](#yrx_compiler_add_source),
but in addition to the source code itself it provides a string that identifies
the origin of the code, usually the file path from where the source was obtained.
This origin is shown in error reports.

------

#### yrx_compiler_add_include_dir

```c
enum YRX_RESULT yrx_compiler_add_include_dir(
    struct YRX_COMPILER *compiler,
    const char *dir);
```

Adds a directory to the list of directories where the compiler should look for included files.

When an `include` is found, the compiler looks for the included file in the directories added
with this function, in the order they were added.

If this function is not called, the compiler will only look for included files in the current
directory.

------

#### yrx_compiler_ignore_module

```c
enum YRX_RESULT yrx_compiler_ignore_module(
    struct YRX_COMPILER *compiler,
    const char *module);
```

Tells the compiler that a YARA module is not supported. Import statements
for ignored modules will be ignored without errors but a warning will be
issued. Any rule that make use of an ignored module will be ignored, while
the rest of rules that don't rely on that module will be correctly compiled.

------

#### yrx_compiler_ban_module

```c
enum YRX_RESULT yrx_compiler_ban_module(
    struct YRX_COMPILER *compiler,
    const char *module,
    const char *error_title,
    const char *error_msg);
```

Tell the compiler that a YARA module can't be used. Import statements for
the banned module will cause an error. The error message can be customized
by using the given error title and message. If this function is called
multiple times with the same module name, the error title and message will
be updated.

------

#### yrx_compiler_new_namespace

```c
enum YRX_RESULT yrx_compiler_new_namespace(
    struct YRX_COMPILER *compiler,
    const char *namespace_);
```

Creates a new namespace. Further calls
to [yrx_compiler_add_source](#yrx_compiler_add_source) will put the
rules under the newly created namespace. The `namespace` argument must be
pointer to null-terminated UTF-8 string. If the string is not valid UTF-8 the
result is an `YRX_INVALID_ARGUMENT` error.

#### yrx_compiler_define_global_xxxx

```c
enum YRX_RESULT yrx_compiler_define_global_str(
    struct YRX_COMPILER *compiler,
    const char *ident,
    const char *value);

enum YRX_RESULT yrx_compiler_define_global_bool(
    struct YRX_COMPILER *compiler,
    const char *ident,
    bool value);

enum YRX_RESULT yrx_compiler_define_global_int(
    struct YRX_COMPILER *compiler,
    const char *ident,
    int64_t value);

enum YRX_RESULT yrx_compiler_define_global_float(
    struct YRX_COMPILER *compiler,
    const char *ident,
    double value);
```

Defines a global variable and sets its initial value.

Global variables must be defined before
calling [yrx_compiler_add_source](#yrx_compiler_add_source) with some YARA rule
that uses the variable. The variable will retain its initial value when the
[YRX_RULES](#yrx_rules) object is used for scanning data, however each scanner
can change the variable's value by
calling any of the [yrx_scanner_set_global_xxxx](#yrx_scanner_set_global_xxxx)
functions.

The `ident` argument must be pointer to null-terminated UTF-8 string. If the
string is not valid UTF-8 the result is an `YRX_INVALID_ARGUMENT` error.

#### yrx_compiler_errors_json

```c
enum YRX_RESULT yrx_compiler_errors_json(
    struct YRX_COMPILER *compiler,
    struct YRX_BUFFER **buf);
```

Returns the errors encountered during the compilation in JSON format. In the
address indicated by the `buf` pointer, the function will copy a `YRX_BUFFER*`
pointer. The `YRX_BUFFER` structure represents a buffer that contains the JSON
representation of the compilation errors. The JSON consists on an array of
objects, each object representing a compilation error.

The object has the following fields:

* `type`: A string that describes the type of error.
* `code`: Error code (e.g: "E009").
* `title`: Error title (e.g: "unknown identifier `foo`").
* `labels`: Array of labels.
* `text`: The full text of the error report, as shown by the command-line tool.

Example:

```json
[
  {
    "type": "error",
    "code": "E009",
    "title": "unknown identifier `foo`",
    "labels": [
      {
        "style": "primary",
        "file_id": 0,
        "range": {
          "start": 26,
          "end": 29
        },
        "message": "identifier `foo` not found"
      }
    ],
    "text": "error[E009]: unknown identifier `foo`\n --> /path/to/rules.yara:2:11\n  |\n2 | condition: foo\n  |           ^^^ identifier `foo` not found\n  |\n  = note: this error occurred in rule `my_rule`"
  }
]
```

The `YRX_BUFFER` must be destroyed with [`yrx_buffer_destroy`](#yrx_buffer_destroy).

------

#### yrx_compiler_warnings_json

```c
enum YRX_RESULT yrx_compiler_warnings_json(
    struct YRX_COMPILER *compiler,
    struct YRX_BUFFER **buf);
```

Returns the warnings encountered during the compilation in JSON format. In the
address indicated by the `buf` pointer, the function will copy a `YRX_BUFFER*`
pointer. The `YRX_BUFFER` structure represents a buffer that contains the JSON
representation of the compilation warnings. The JSON consists on an array of
objects, each object representing a warning.

The object has the following fields:

* `type`: A string that describes the type of warning.
* `code`: Warning code (e.g: "slow_pattern").
* `title`: Warning title (e.g: "slow pattern").
* `labels`: Array of labels.
* `text`: The full text of the warning report, as shown by the command-line tool.

Example:

```json
[
  {
    "type": "warning",
    "code": "slow_pattern",
    "title": "slow pattern",
    "labels": [
      {
        "style": "primary",
        "file_id": 0,
        "range": {
          "start": 10,
          "end": 18
        },
        "message": "this pattern is slow and may impact scanning performance"
      }
    ],
    "text": "warning: slow pattern\n --> /path/to/rules.yara:1:12\n  |\n1 |   $hex = { AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 }\n  |            ^^^^^^^^ this pattern is slow and may impact scanning performance\n  |\n  = note: this warning occurred in rule `my_rule`"
  }
]
```

The `YRX_BUFFER` must be destroyed with [`yrx_buffer_destroy`](#yrx_buffer_destroy).

------

#### yrx_compiler_build

```c
struct YRX_RULES *yrx_compiler_build(struct YRX_COMPILER *compiler);
```

Builds the source code previously added to the compiler, producing
a [YRX_RULES](#yrx_rules) object that can be used for scanning data.

The [YRX_RULES](#yrx_rules) object must be destroyed
with [yrx_rules_destroy](#yrx_rules_destroy) when not used anymore.

After calling this function the compiler is reset to its initial state,
you can keep using it by adding more sources and calling this function again.

### YRX_RULES

Type that represents a set of compiled rules. The compiled rules can be used for
scanning data by creating a scanner
with [yrx_scanner_create](#yrx_scanner_create).

#### yrx_rules_count

```c
int yrx_rules_count(struct YRX_RULES *rules);
```

Returns the total number of rules. The result is -1 in case of error.

#### yrx_rules_destroy

```c
void yrx_rules_destroy(struct YRX_RULES *rules);
```

Destroys the [YRX_RULES](#yrx_rules) object. This function must be called only
after all the scanners using the  [YRX_RULES](#yrx_rules) object are destroyed.

#### yrx_rules_iter

```c
enum YRX_RESULT yrx_rules_iter(
    const struct YRX_RULES *rules,
    YRX_RULE_CALLBACK callback,
    void *user_data);
```

Iterates over the compiled rules, calling the callback function for each rule.
The `user_data` pointer can be used to provide additional context to your
callback function. See [YRX_RULE_CALLBACK](#yrx_rule_callback) for more details.

#### yrx_rules_iter_imports

```c
enum YRX_RESULT yrx_rules_iter_imports(
    const struct YRX_RULES *rules,
    YRX_IMPORT_CALLBACK callback,
    void *user_data);
```

Iterates over the modules imported by the rules, calling the callback with the
name of each imported module.

The `user_data` pointer can be used to provide additional context to your callback
function.

See [YRX_IMPORT_CALLBACK](#yrx_import_callback) for more details.


#### yrx_rules_serialize

```c
enum YRX_RESULT yrx_rules_serialize(
    const struct YRX_RULES *rules, 
    struct YRX_BUFFER **buf);
```

Serializes the rules as a sequence of bytes.

In the address indicated by the `buf` pointer, the function will copy a
`YRX_BUFFER*` pointer. The [YRX_BUFFER](#yrx_buffer) structure represents a buffer
that contains the serialized rules. This structure has a pointer to the data 
itself, and its length.

The [YRX_BUFFER](#yrx_buffer) must be destroyed with [yrx_buffer_destroy](#yrx_buffer_destroy).

#### yrx_rules_deserialize

```c
enum YRX_RESULT yrx_rules_deserialize(
    const uint8_t *data,
    size_t len,
    struct YRX_RULES **rules);
```

Deserializes the rules from a sequence of bytes produced by [yrx_rules_serialize](#yrx_rules_serialize).



------

### YRX_SCANNER

#### yrx_scanner_create

```c
enum YRX_RESULT yrx_scanner_create(
    const struct YRX_RULES *rules,
    struct YRX_SCANNER **scanner);
```

Creates a [YRX_SCANNER](#yrx_scanner) object that can be used for scanning data
with the provided [YRX_RULES](#yrx_rules).

It's ok to pass the same [YRX_RULES](#yrx_rules) to multiple scanners, and use
each scanner from a different thread. The scanner can be used as many times as
you want, and it must be destroyed
with [yrx_scanner_destroy](#yrx_scanner_destroy). Also, the scanner is valid as
long as the rules are not destroyed, so, always destroy
the [YRX_SCANNER](#yrx_scanner) object before the [YRX_RULES](#yrx_rules)
object.

#### yrx_scanner_destroy

```c
void yrx_scanner_destroy(struct YRX_SCANNER *scanner);
```

Destroys the [YRX_SCANNER](#yrx_scanner) object.

#### yrx_scanner_on_matching_rule

```c 
enum YRX_RESULT yrx_scanner_on_matching_rule(
    struct YRX_SCANNER *scanner,
    YRX_ON_MATCHING_RULE callback,
    void *user_data);
```

Sets a callback function that is called by the scanner for each rule that
matched during a scan.

The `user_data` pointer can be used to provide additional context to your
callback function. If the callback is not set, the scanner doesn't notify
about matching rules.

See [YRX_ON_MATCHING_RULE](#yrx_on_matching_rule) for more details.

#### yrx_scanner_scan

```c 
enum YRX_RESULT yrx_scanner_scan(
    struct YRX_SCANNER *scanner,
    const uint8_t *data,
    size_t len);
```

#### yrx_scanner_set_timeout

```c
enum YRX_RESULT yrx_scanner_set_timeout(
    struct YRX_SCANNER *scanner,
    uint64_t timeout);
```

#### yrx_scanner_set_global_xxxx

```c
enum YRX_RESULT yrx_scanner_set_global_str(
    struct YRX_SCANNER *scanner,
    const char *ident,
    const char *value);

enum YRX_RESULT yrx_scanner_set_global_bool(
    struct YRX_SCANNER *scanner,
    const char *ident,
    bool value);

enum YRX_RESULT yrx_scanner_set_global_int(
    struct YRX_SCANNER *scanner,
    const char *ident,
    int64_t value);

enum YRX_RESULT yrx_scanner_set_global_float(
    struct YRX_SCANNER *scanner,
    const char *ident,
    double value);
```

------

#### yrx_scanner_set_module_output

```c
enum YRX_RESULT yrx_scanner_set_module_output(
    struct YRX_SCANNER *scanner,
    const char *name,
    const uint8_t *data,
    size_t len);
```

Specifies the output data structure for a YARA module. Each module can generate
an output, typically a Protocol Buffer, containing information about the scanned
file. This function allows you to provide this output data yourself in two 
scenarios:

1.  **Module without auto-output**: If a module doesn't generate output on its 
    own (e.g., lacks a main function), you must use this function to set its output 
    before scanning.
2.  **Reusing known output**: If you have already processed a file and know 
    the module's output, you can provide it via this function to avoid redundant 
    computation by the module, potentially improving performance.

The module's output is consumed after each call to [`yrx_scanner_scan`](#yrx_scanner_scan). 
Therefore, if you need to provide it, you must call this function before each scan.
This function receives:

*   `scanner`: A pointer to the [`YRX_SCANNER`](#yrx_scanner) instance.
*   `name`: A null-terminated UTF-8 string. This can be either the YARA module
     name (e.g., "pe", "elf") or the fully-qualified name of the module's protobuf message.
*   `data`: A pointer to the buffer containing the serialized protobuf data.
*   `len`: The length of the data buffer in bytes.

------

#### yrx_scanner_set_module_data

```c
enum YRX_RESULT yrx_scanner_set_module_data(
    struct YRX_SCANNER *scanner,
    const char *name,
    const uint8_t *data,
    size_t len);
```

Specifies metadata for a YARA module. Similar to module output, module metadata
is typically specific to each scanned file and is consumed after each call to 
[`yrx_scanner_scan`](#yrx_scanner_scan). Thus, you need to call this function 
before each scan if you intend to provide custom module metadata. It receives:

*   `scanner`: A pointer to the [`YRX_SCANNER`](#yrx_scanner) instance.
*   `name`: A null-terminated UTF-8 string representing the YARA module name.
*   `data`: A pointer to the buffer containing the module data.
*   `len`: The length of the data buffer in bytes.

The provided `name` and `data` pointers must remain valid from the time this
function is called until the scan is executed.

------

#### yrx_scanner_iter_slowest_rules

```c
enum YRX_RESULT yrx_scanner_iter_slowest_rules(
    struct YRX_SCANNER *scanner,
    size_t n,
    YRX_SLOWEST_RULES_CALLBACK callback,
    void *user_data);
```

Iterates over the `n` slowest rules encountered by the scanner, invoking the
provided callback for each one. This function is used for profiling rule 
performance, it receives:

*   `scanner`: A pointer to the [YRX_SCANNER](#yrx_scanner) instance.
*   `n`: The maximum number of slowest rules to report.
*   `callback`: A function pointer of type [YRX_SLOWEST_RULES_CALLBACK](#yrx_slowest_rules_callback)
     that will be invoked for each of the slowest rules.
*   `user_data`: A void pointer to arbitrary user data that will be passed to
     the callback function.

**Note:** This function requires the `rules-profiling` feature to be enabled
when YARA-X is compiled. If the feature is not available, this function will
return `YRX_NOT_SUPPORTED`.

See also: 
 * [YRX_SLOWEST_RULES_CALLBACK](#yrx_slowest_rules_callback)
 * [yrx_scanner_clear_profiling_data](#yrx_scanner_clear_profiling_data).

------

#### yrx_scanner_clear_profiling_data

```c
enum YRX_RESULT yrx_scanner_clear_profiling_data(
    struct YRX_SCANNER *scanner);
```

Clears all accumulated rule profiling data from the scanner. This is useful when
you want to start a new profiling session and ensure that the results from 
[yrx_scanner_iter_slowest_rules](#yrx_scanner_iter_slowest_rules) only reflect
scans performed after calling this function.

**Note:** This function requires the `rules-profiling` feature to be enabled
when YARA-X is compiled. If the feature is not available, this function will 
return `YRX_NOT_SUPPORTED`.

See also:
* [yrx_scanner_iter_slowest_rules](#yrx_scanner_iter_slowest_rules)

------

### YRX_ON_MATCHING_RULE

```c
typedef void (*YRX_ON_MATCHING_RULE)(
    const struct YRX_RULE *rule,
    void *user_data);
```

Callback function passed to the scanner
via [yrx_scanner_on_matching_rule](#yrx_on_matching_rule), which receives
notifications about matching rules.

The callback receives a pointer to the matching rule, represented by a
[YRX_RULE](#yrx_rule) structure. This pointer is guaranteed to be valid while
the callback function is being executed, but it may be freed after the callback
function returns, so you cannot use the pointer outside the callback.

It also receives the `user_data` pointer that was passed to
[yrx_scanner_on_matching_rule](#yrx_scanner_on_matching_rule), which can point
to arbitrary data owned by the user.

------

### YRX_RULE

Represents a single YARA rule. The callback function passed to the scanner
for reporting matches receives a pointer to a [YRX_RULE](#yrx_rule).

#### yrx_rule_identifier

```c
enum YRX_RESULT yrx_rule_identifier(
    const struct YRX_RULE *rule,
    const uint8_t **ident,
    size_t *len);
```

Returns the identifier of the rule represented by `rule`.

Arguments `ident` and `len` are output parameters that receive pointers to a
`const uint8_t*` and `size_t`, where this function will leave a pointer
to the rule's identifier and its length, respectively. The identifier is **NOT**
null-terminated, you must use the returned `len` as the size of the identifier.
The `*ident` pointer will be valid as long as the [YRX_RULES](#yrx_rules) object
that contains the rule is not destroyed. The identifier is guaranteed to be a
valid UTF-8 string.

#### yrx_rule_namespace

```c
enum YRX_RESULT yrx_rule_namespace(
    const struct YRX_RULE *rule,
    const uint8_t **ns,
    size_t *len);
```

Returns the namespace of the rule represented by `rule`.

Arguments `ns` and `len` are output parameters that receive pointers to a
`const uint8_t*` and `size_t`, where this function will leave a pointer
to the rule's namespace and its length, respectively. The namespace is **NOT**
null-terminated, you must use the returned `len` as the size of the namespace.
The `*ns` pointer will be valid as long as the [YRX_RULES](#yrx_rules) object
that contains the rule is not destroyed. The namespace is guaranteed to be a
valid UTF-8 string.

#### yrx_rule_iter_metadata

```c
struct YRX_METADATA *yrx_rule_iter_metadata(
    const struct YRX_RULE *rule,
    YRX_METADATA_CALLBACK callback,
    void *user_data);
```

Iterates over the metadata of a rule, calling the callback with a pointer
to a [YRX_METADATA](#yrx_metadata) structure for each metadata in the rule.

The `user_data` pointer can be used to provide additional context to your
callback function.

#### yrx_rule_iter_patterns

```c
struct YRX_PATTERNS *yrx_rule_iter_patterns(
    const struct YRX_RULE *rule,
    YRX_PATTERN_CALLBACK callback,
    void *user_data);
```

Iterates over the patterns in a rule, calling the callback with a pointer
to a [YRX_PATTERN](#yrx_pattern) structure for each pattern.

The `user_data` pointer can be used to provide additional context to your
callback function.

#### yrx_rule_iter_tags

```c
enum YRX_RESULT yrx_rule_iter_tags(
    const struct YRX_RULE *rule,
    YRX_TAG_CALLBACK callback,
    void *user_data);
```

Iterates over the tags in a rule, calling the callback with a pointer to each
tag. The `user_data` pointer can be used to provide additional context to your
callback function. See `YRX_TAG_CALLBACK` for more details.

------

### YRX_PATTERN

An individual pattern defined in a rule.

#### yrx_pattern_identifier

```c
enum YRX_RESULT yrx_pattern_identifier(
    const struct YRX_PATTERN *pattern,
    const uint8_t **ident,
    size_t *len);
```

Returns the identifier of the pattern represented by `pattern`.

Arguments `ident` and `len` are output parameters that receive pointers to a
`const uint8_t*` and `size_t`, where this function will leave a pointer
to the patterns's identifier and its length, respectively. The identifier is
**NOT** null-terminated, you must use the returned `len` as the size of the
identifier. The `*ident` pointer will be valid as long as
the [YRX_RULES](#yrx_rules) object that contains the rule defining this pattern
is not destroyed. The identifier is guaranteed to be a valid UTF-8 string.

#### yrx_pattern_iter_matches

```c
enum YRX_RESULT yrx_pattern_iter_matches(
    const struct YRX_PATTERN *pattern,
    YRX_MATCH_CALLBACK callback,
    void *user_data);
```

Iterates over the matches of a pattern, calling the callback with a pointer
to a [YRX_MATCH](#yrx_match) structure for each pattern.

The `user_data` pointer can be used to provide additional context to your
callback function.

------

### YRX_MATCH

An individual match found for a pattern. The [YRX_PATTERN](#yrx_pattern)
object has a pointer to an array of these structures.

```c
typedef struct YRX_MATCH {
    size_t offset;
    size_t length;
} YRX_MATCH;
```

------

### YRX_METADATA

Represents a metadata entry in a rule. You will get a pointer to one of these
structures from the callback passed
to [yrx_rule_iter_metadata](#yrx_rule_iter_metadata)

```c
typedef struct YRX_METADATA {
    // Metadata identifier.
    const char *identifier;
    // Metadata type.
    enum YRX_METADATA_TYPE value_type;
    // Metadata value.
    //
    // This a union type, the variant that should be used is determined by the
    // type indicated in `value_type`.
    union YRX_METADATA_VALUE value;
} YRX_METADATA;

```

------

### YRX_METADATA_TYPE

Each of the possible types of a metadata entry.

```c
typedef enum YRX_METADATA_TYPE {
    YRX_I64,
    YRX_F64,
    YRX_BOOLEAN,
    YRX_STRING,
    YRX_BYTES,
} YRX_METADATA_VALUE_TYPE;
```

------

### YRX_METADATA_VALUE

Union that represents a metadata value.

```c
typedef union YRX_METADATA_VALUE {
    int64_t i64;
    double f64;
    bool boolean;
    char *string;
    struct YRX_METADATA_BYTES bytes;
} YRX_METADATA_VALUE;
```

------

### YRX_METADATA_BYTES

Structure that represents a metadata value with an arbitrary sequence of bytes.

```c
typedef struct YRX_METADATA_BYTES {
    // Number of bytes.
    size_t length;
    // Pointer to the bytes.
    uint8_t *data;
} YRX_METADATA_BYTES;
```

------

### YRX_RESULT

Error codes returned by multiple functions in this API.

```c
typedef enum YRX_RESULT {
    // Everything was OK.
    YRX_SUCCESS,
    // A syntax error occurred while compiling YARA rules.
    YRX_SYNTAX_ERROR,
    // An error occurred while defining or setting a global variable. This may
    // happen when a variable is defined twice and when you try to set a value
    // that doesn't correspond to the variable's type.
    YRX_VARIABLE_ERROR,
    // An error occurred during a scan operation.
    YRX_SCAN_ERROR,
    // A scan operation was aborted due to a timeout.
    YRX_SCAN_TIMEOUT,
    // An error indicating that some of the arguments passed to a function is
    // invalid. Usually indicates a nil pointer to a scanner or compiler.
    YRX_INVALID_ARGUMENT,
    // An error indicating that some of the strings passed to a function is
    // not valid UTF-8.
    YRX_INVALID_UTF8,
    // An error occurred while serializing/deserializing YARA rules.
    YRX_SERIALIZATION_ERROR,
    // An error returned when a rule doesn't have any metadata.
    YRX_NO_METADATA,
    // An error returned in cases where some API is not supported because the
    // library was not built with the required features.
    YRX_NOT_SUPPORTED,
} YRX_RESULT;
```

### YRX_RULE_CALLBACK

```c
typedef void (*YRX_RULE_CALLBACK)(
    const struct YRX_RULE *rule,
    void *user_data);
```

Callback function passed to [yrx_scanner_on_matching_rule](#yrx_scanner_on_matching_rule) or
[yrx_rules_iter](#yrx_rules_iter).

The callback receives a pointer to a rule, represented by a [YRX_RULE](#yrx_rule)
structure. This pointer is guaranteed to be valid while the callback
function is being executed, but it may be freed after the callback function
returns, so you cannot use the pointer outside the callback.

It also receives the `user_data` pointer that can point to arbitrary data
owned by the user.


### YRX_IMPORT_CALLBACK

```c
typedef void (*YRX_IMPORT_CALLBACK)(
    const char *module_name,
    void *user_data);
```

Callback function passed to [yrx_rules_iter_imports](#yrx_rules_iter_imports).

The callback is called for every module imported by the rules, and it
receives a pointer to the module's name. This pointer is guaranteed to be
valid while the callback function is being executed, but it will be freed
after the callback function returns, so you cannot use the pointer outside
the callback.

The callback also receives a `user_data` pointer that can point to arbitrary
data owned by the user.

### YRX_MATCH_CALLBACK

```c
typedef void (*YRX_MATCH_CALLBACK)(
    const struct YRX_MATCH *match,
    void *user_data);
```

Callback function passed to [yrx_pattern_iter_matches](#yrx_pattern_iter_matches).

The callback is invoked for every match found for a specific pattern. It receives:
*   A pointer to a [YRX_MATCH](#yrx_match) structure containing details about the
    match. This pointer is only valid for the duration of the callback.
*   The `user_data` pointer that was passed to [yrx_pattern_iter_matches](#yrx_pattern_iter_matches).

------

### YRX_METADATA_CALLBACK

```c
typedef void (*YRX_METADATA_CALLBACK)(
    const struct YRX_METADATA *metadata,
    void *user_data);
```

Callback function passed to [yrx_rule_iter_metadata](#yrx_rule_iter_metadata).

The callback is invoked for each metadata item associated with a rule. It receives:
*   A pointer to a [YRX_METADATA](#yrx_metadata) structure. This pointer is only 
    valid for the duration of the callback.
*   The `user_data` pointer that was passed to [yrx_rule_iter_metadata](#yrx_rule_iter_metadata).

------

### YRX_PATTERN_CALLBACK

```c
typedef void (*YRX_PATTERN_CALLBACK)(
    const struct YRX_PATTERN *pattern,
    void *user_data);
```

Callback function passed to [yrx_rule_iter_patterns](#yrx_rule_iter_patterns).

The callback is invoked for each pattern defined within a rule. It receives:
*   A pointer to a [YRX_PATTERN](#yrx_pattern) structure. This pointer is only  
    valid for the duration of the callback.
*   The `user_data` pointer that was passed to [yrx_rule_iter_patterns](#yrx_rule_iter_patterns).

------

### YRX_TAG_CALLBACK

```c
typedef void (*YRX_TAG_CALLBACK)(
    const char *tag,
    void *user_data);
```

Callback function passed to [yrx_rule_iter_tags](#yrx_rule_iter_tags).

The callback is invoked for each tag associated with a rule. It receives:
*   A pointer to a null-terminated string representing the tag. This pointer is only
    valid for the duration of the callback.
*   The `user_data` pointer that was passed to [yrx_rule_iter_tags](#yrx_rule_iter_tags).

------

### YRX_SLOWEST_RULES_CALLBACK

```c
typedef void (*YRX_SLOWEST_RULES_CALLBACK)(
    const char *namespace_,
    const char *rule_name,
    double pattern_matching_time,
    double condition_evaluation_time,
    void *user_data);
```

Callback function passed to [`yrx_scanner_iter_slowest_rules`](#yrx_scanner_iter_slowest_rules).

This callback is invoked to report information about the slowest rules during a scan. It receives:
*   `namespace_`: A pointer to a null-terminated string for the rule's namespace.
*   `rule_name`: A pointer to a null-terminated string for the rule's name.
*   `pattern_matching_time`: Time spent in pattern matching for this rule (in seconds).
*   `condition_evaluation_time`: Time spent evaluating the rule's condition (in seconds).
*   The `user_data` pointer that was passed to [`yrx_scanner_iter_slowest_rules`](#yrx_scanner_iter_slowest_rules).

The string pointers (`namespace_`, `rule_name`) are only valid for the duration of the callback.
This callback is only available if the `rules-profiling` feature was enabled during compilation.

------

### YRX_BUFFER

Represents a buffer with arbitrary data. Some functions in this API like
[yrx_compiler_errors_json](#yrx_compiler_errors_json) and 
[yrx_compiler_warnings_json](#yrx_compiler_warnings_json)
create buffers and return pointers to them.


```c
typedef struct YRX_BUFFER {
  // Pointer to the data contained in the buffer.
  uint8_t *data;
  // Length of data in bytes.
  size_t length;
} YRX_BUFFER;
```

------

#### yrx_buffer_destroy

```c
void yrx_buffer_destroy(struct YRX_BUFFER *buf);
```

Destroys a `YRX_BUFFER` object.

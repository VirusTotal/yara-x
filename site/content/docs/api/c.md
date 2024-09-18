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
* A [module definition file]() `yara_x_capi.def`
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
result is an `INVALID_ARGUMENT` error.

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
string is not valid UTF-8 the result is an `INVALID_ARGUMENT` error.

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

------ 

### YRX_RULES

Type that represents a set of compiled rules. The compiled rules can be used for
scanning data by creating a scanner
with [yrx_scanner_create](#yrx_scanner_create).

#### yrx_rules_destroy

```c
void yrx_rules_destroy(struct YRX_RULES *rules);
```

Destroys the [YRX_RULES](#yrx_rules) object. This function must be called only
after all the scanners using the  [YRX_RULES](#yrx_rules) object are destroyed.

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
    I64,
    F64,
    BOOLEAN,
    STRING,
    BYTES,
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
    SUCCESS,
    // A syntax error occurred while compiling YARA rules.
    SYNTAX_ERROR,
    // An error occurred while defining or setting a global variable. This may
    // happen when a variable is defined twice and when you try to set a value
    // that doesn't correspond to the variable's type.
    VARIABLE_ERROR,
    // An error occurred during a scan operation.
    SCAN_ERROR,
    // A scan operation was aborted due to a timeout.
    SCAN_TIMEOUT,
    // An error indicating that some of the arguments passed to a function is
    // invalid. Usually indicates a nil pointer to a scanner or compiler.
    INVALID_ARGUMENT,
    // An error indicating that some of the strings passed to a function is
    // not valid UTF-8.
    INVALID_UTF8,
    // An error occurred while serializing/deserializing YARA rules.
    SERIALIZATION_ERROR,
} YRX_RESULT;
```
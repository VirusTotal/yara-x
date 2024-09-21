Module Developer's Guide
========================

YARA modules are the way in which you can extend YARA's capabilities by
adding new data structures and functions that can be later used in your rules,
making them more powerful and expressive. For example, a YARA module can
parse a file format and expose to YARA any information extracted from the
file that may be useful while creating YARA rules.

This document will guide you through the process of creating a YARA module.
For illustrative purposes we are going to create a `text` module that allows
creating YARA rules for plain-text files, based on the number of lines and
words

- [Defining the module's structure](#defining-the-modules-structure)
- [Proto2 vs Proto3](#proto2-vs-proto3)
- [Tweaking the module's YAML output](#tweaking-the-modules-yaml-output)
- [Implementing the module's main function](#implementing-the-modules-main-function)
- [Building your module](#building-your-module)
- [Adding functions to your module](#adding-functions-to-your-module)
    - [Valid function arguments](#valid-function-arguments)
    - [Valid return types](#valid-return-types)
- [String types in module functions](#string-types-in-module-functions)
- [Accessing the module's structure from a function](#accessing-the-modules-structure-from-a-function)
- [Adding dependencies](#adding-dependencies)
- [Using enums](#using-enums)
    - [Inline enums](#inline-enums)
- [Tests](#tests)
    - [Structuring Testdata Input](#structuring-testdata-input)
        - [Linux](#linux)
        - [MacOS](#macos)
        - [Other Operating Systems](#other-operating-systems)
        - [Archiving the test data](#archiving-the-test-data)
    - [Converting the Files back to Original Format](#converting-the-files-back-to-original-format)
        - [Unarchiving the test data](#unarchiving-the-test-data)
        - [Linux](#linux-1)
        - [MacOS](#macos-1)
        - [Other Operating Systems](#other-operating-systems-1)

## Defining the module's structure

Most YARA modules define a data structure that is filled with information
extracted from the scanned file and exposed to YARA with the purpose of being
used in your rules. In YARA-X this structure is defined by using
[Protocol Buffers](https://developers.google.com/protocol-buffers) (protobuf
from now on). The first thing you must do when creating your module is
writing the protobuf that defines the module's structure. If you are not
familiar
with protobufs we recommend you to start by exploring its documentation and
getting used to its syntax. You don't need to become an expert in protobufs for
being able to define a YARA module, but some familiarity will certainly help.

Let's start defining the structure for our `text` module. For that, you must
create a `text.proto` file and put it into the `yara-x/src/modules/protos`
directory. As a starting point we can use the following file:

```protobuf
syntax = "proto2";

import "yara.proto";

package text;

option (yara.module_options) = {
  name : "text"
  root_message: "text.Text"
  rust_module: "text"
  cargo_feature: "text-module"
};

message Text {
  optional int64 num_lines = 1;
  optional int64 num_words = 2;
}
```

This is a very simple module that exposes only two fields: `num_lines` and
`num_words`. Let's dissect the content of `text.proto` line by line:

```protobuf
syntax = "proto2";
```

This indicates which version of the protobuf syntax you are going to use. There
are two possibilities here: `proto2` and `proto3`. We are going to talk about
the differences between the two in [Proto2 vs Proto3](#proto2-vs-proto3), but
for the time being let's use `proto2`. By the way, `proto2` is the default
if you don't specify the syntax version, which means that the first line in
the file is actually optional. However, we recommend making your choice
explicit by always including this line at the beginning of your file. Let's
see the next line:

```protobuf
import "yara.proto";
```

With this line we are importing certain YARA-specific definitions that will be
used later in the `proto` file. This line is required.

----

**NOTE**: If you are curious about the content of `yara.proto` you can find it
at`yara-x-proto/src/yara.proto`.

----

```protobuf
package text;
```

The package statement is optional but highly recommended, as it prevents name
collisions between different YARA modules. If modules `foo` and `bar` both
define a structure named `Foobar` without specifying their own package names
it will confuse the `protoc` compiler when producing the Rust code for your
module. The resulting code can use `foo.Foobar` instead of `bar.Foobar` in
code generated for the `bar` module.

Let's start with the interesting part:

```protobuf
option (yara.module_options) = {
  name : "text"
  root_message: "text.Text"
  rust_module: "text"
  cargo_feature: "text-module"
};
```

The snippet above is also required for every `.proto` file that describes a
YARA module. This is what tells that this file is not an ordinary `.proto`
file, but one describing a module. In fact, you can put any `.proto` file in the
`yara-x/src/modules/protos` directory, and that doesn't mean that each of those
files is describing a YARA module. Only files containing a `yara.module_options`
section will define a module.

Options `name` and `root_message` are required, while `rust_module` and
`cargo_feature` are optional. The `name` option defines the module's name. This
is the name that will be used for importing the module in a YARA rule, in this
case our module will be imported with `import "text"`.

The `cargo_feature` option indicates the name of the feature that controls
whether
the module is built or not. If this option is not specified the module is always
built, but if you specify a feature name, this feature name must also be
included
in the `Cargo.toml` file, and the module will be built only when this `cargo`
feature is enabled.

The `root_message` option a very important option indicating which is the
module's
root structure, it must contain the name of some structure (a.k.a. message)
defined in the `.proto` file. In our case the value for `root_message` is
`"text.Text"` because we have defined our module's structure in a message named
`Text`, which is under package `text`. In general the value in this field will
have the form `package.Message`, except if the `package` statement is missing,
in which case it would be the name of the message alone (i.e: `Text`).

The `root_message` field is required because your `.proto` file can define
multiple messages, and YARA needs to know which of them is considered the root
message for the module. Without this field YARA can't know which message to
use.

And here is our root structure/message:

```protobuf
message Text {
  optional int64 num_lines = 1;
  optional int64 num_words = 2;
}
```

This is a very simple structure with only two integer fields. Notice that the
numbers after the `=` signs are not the values for those fields, they are
actually field tags (i.e: a unique number identifying each field in a message).
This may be confusing if you are not familiar with protobuf's syntax, so again:
explore the
protobuf's [documentation](https://developers.google.com/protocol-buffers).

Also notice that we are defining our fields as `optional`. In `proto2` fields
must be either `optional` or `required`, while in `proto3` they are always
optional and can't be forced to be required. We are going to discuss this topic
more in-depth in the [Proto2 vs Proto3](#proto2-vs-proto3) section.

With this we have defined a very simple module that could be used in a YARA
rule like this:

```yara
import "text"

rule text_with_100_words {
    condition:
        text.num_words == 100
}
```

Of course, we are not done yet. So far we have defined the structure of our
module, but we need to populate that structure with actual values extracted from
the scanned files. That's where the module's main function enters into play. But
before going into the details of how to implement this function, let's discuss
the differences between `proto2` and `proto3`, as they may determine some
aspects
of our implementation.

## Proto2 vs Proto3

When writing a YARA module you can choose between `proto2` and `proto3` for
writing the protobuf that describes your module's structure. Both of them
are very similar, but they also have some differences.

One of the most important differences is that in `proto2` fields are either
`optional` or `required`, while in `proto3` all fields are optional, and
therefore
the keywords `optional` and `required` are not accepted at all. But this
difference
goes beyond a simple syntactic matter, it also affects the way in which missing
fields are handled.

In `proto2`, when some structure contains a `required` field, this field must
be initialized to some value before the structure gets serialized. If you don't
provide a value for a `required` field, an error occurs while serializing the
structure. In the other hand, `optional` fields don't need to be initialized,
they simply won't be included in the serialized data, and they will be missing
after the data is deserialized. In fact, if you have a
field `optional int64 foo`
in your protobuf, the corresponding Rust structure will have a field
`foo: Option<i64>`. If `foo` is not initialized, its value after deserializing
the structure will be `None`. This means that in `proto2` you can know whether
the field `foo` was originally initialized to some value, or it was simply left
uninitialized.

In `proto3` things are a bit different. All fields in `proto3` are optional,
but uninitialized fields will default to a value that depends on the type.
For example, for numeric fields the default value is zero, and for string fields
the default value is the empty string. This means that in `proto3` a protobuf
field `int64 foo` is translated into a field `foo: i64`. If `foo` is not
initialized, it will behave as if it was initialized to 0. After deserializing
your structure, you won't be able to tell if `foo` was explicitly set to 0,
or if it was left uninitialized.

This subtle difference is important when creating a YARA module, because
YARA has the concept of `undefined` values. A value in YARA is `undefined` when
it hasn't been initialized to some meaningful value. When `proto2` is used for
defining the structure of your module, uninitialized fields will have an
`undefined` value. In the other hand, when `proto3` is used all fields will
have a value, even if you don't initialize it explicitly. If a field is not
initialized it will have its corresponding default value.

The bottom line is that with `proto3` you won't be able to have fields with
`undefined` values. In some cases that may be what you need, and using `proto3`
is very useful in such cases, as you don't need to explicitly initialize all
the fields in your structure.

## Tweaking the module's YAML output

The `yr dump` command outputs the structure generated by one or more YARA
modules, presenting the information in either JSON or YAML format. The default
output format is YAML, because of its inherent human-friendly nature.
Nevertheless, you can help YARA to further enhance the quality of produced
YAML outputs.

Certain integer fields find a more intuitive representation in hexadecimal
rather than decimal format. To communicate this preference to YARA, a dedicated
configuration option can be employed. Consider the following illustrative
example:

```
message Macho {
  optional uint32 magic = 1 [(yaml.field).fmt = "x"];
}
```

Here, `[(yaml.field).fmt = "x"]` instructs YARA to portray the magic field in
hexadecimal format (i.e., "x"). Consequently, the output will display
`magic: 0xfeedfacf` instead of the less readable `magic: 4277009103`.

Supported format options also includes `"t"` for timestamps. For example:

```
optional uint32 my_timestamp = 1 [(yaml.field).fmt = "t"];
```

In this scenario, the output would be rendered as follows:

```yaml
my_timestamp: 999999999 # 2001-09-09 01:46:39 UTC
```

## Implementing the module's main function

Once you have a `.proto` file that describes the structure of your module you
need write the logic that parses every scanned file and fills the module's
structure with the data obtained from the file. This is done by implementing
a function that will act as the entry point for your module.

This is where the `rust_module` option described in the previous section enters
into play. This option is the name of the Rust module that contains the code
for your module. In our `text.proto` file we have `rust_module: "text"`, which
means that our Rust module must be named `text`.

There are two options for creating our `text` module:

* Creating a `text.rs` file in `yara-x/src/modules`.
* Creating a directory `yara-x/src/modules/text` containing a`mod.rs` file.

For simple modules that can be contained in a single `.rs` file the first
approach is enough. For more complex modules with multiple source files the
second approach is the recommended one.

So, let's create our `yara-x/src/modules/text.rs` file:

```rust
use crate::modules::prelude::*;
use crate::modules::protos::text::*;

#[module_main]
fn main(data: &[u8]) -> Text {
    let mut text_proto = Text::new();

    // TODO: parse the data and populate text_proto.

    text_proto
}
```

This is the simplest possible code for a YARA module, and it doesn't do anything
special yet. Let's describe what it does in detail:

```rust
use crate::modules::prelude::*;
```

This first line is very important as it imports all the dependencies required
by a YARA module. All your modules must start by importing the module's
prelude, otherwise compilation will fail.

```rust
use crate::modules::protos::text::*;
```

Here we are importing all the Rust types automatically generated from our
`text.proto` file. This includes the `Text` structure, which represents the
`Text` message declared in the proto file.

---

**NOTE**: If your protobuf file is `foobar.proto`, the module created for it
will be `crate::modules::protos::foobar`

---

Next comes the module's main function:

```rust
#[module_main]
fn main(data: &[u8]) -> Text {
    ...
}
```

The module's main function is called for every file scanned by YARA. This
function receives a byte slice with the content of the file being scanned. It
must return the `Text` structure that was generated from the `text.proto` file.
The main function must have the `#[module_main]` attribute. Notice that the
module's main function doesn't need to be called `main`, it can have any
arbitrary name, as long as it has the `#[module_main]` attribute. Of course,
this attribute can't be used with more than one function per module.

The main function usually consists in creating an instance of the protobuf
you previously defined, and populating the protobuf with information extracted
from
the scanned file. Let's finish the implementation of the main function for our
`text` module.

```rust 
use crate::modules::prelude::*;
use crate::modules::protos::text::*;

use std::io;
use std::io::BufRead;

#[module_main]
fn main(data: &[u8]) -> Text {
    // Create an empty instance of the Text protobuf.
    let mut text_proto = Text::new();

    let mut num_lines = 0;
    let mut num_words = 0;

    // Create cursor for iterating over the lines.
    let cursor = io::Cursor::new(data);

    // Count the lines and words in the file.
    for line in cursor.lines() {
        match line {
            Ok(line) => {
                num_words += line.split_whitespace().count();
                num_lines += 1;
            }
            Err(_) => return text_proto,
        }
    }

    // Set the value for fields `num_lines` and `num_words` in the protobuf.
    text_proto.set_num_lines(num_lines as i64);
    text_proto.set_num_words(num_words as i64);

    // Return the Text proto after filling the relevant fields.
    text_proto
}
```

That's all you need for having a fully functional YARA module. Now, let's build
it!

## Building your module

After creating the files `yara-x/src/modules/protos/text.proto` and
`yara-x/src/modules/text.rs` we are almost ready for building the module into
YARA. But there are few more pending steps.

The first thing that you must know is that your module is behind a `cargo`
feature
flag. The module won't be built into YARA unless you tell `cargo` to do so. The
name of the feature controlling your module is `text-module`, and this feature
must be added to the `[features]` section in the `yara-x/Cargo.toml` file.

```toml
[features]
text-module = []  # Add this line to yara-x/Cargo.toml
```

Additionally, if you want your module to be included by default in YARA, add
the feature name to the `default` list in the `[features]` section of
`yara-x/Cargo.toml`:

```toml
[features]
text-module = []

# Features that are enabled by default.
default = [
    "constant-folding",
    "test_proto2-module",
    "test_proto3-module",
    "text-module"  # The text module will be included by default
]
```

If the module's feature flag is not added to the `default` list, you must
explicitly tell `cargo` that you want to build YARA with your module:

```shell
cargo build --features=text-module
```

---

**NOTE**: The name of the feature flag depends on the module's name. If the
module's name is `foobar`, the feature flag is `foobar-module`.

---

Congratulations! Now your `text` module can be used!

## Adding functions to your module

YARA modules not only expose structured data that can be used in rules. They
also allow to expose functions that can be called from YARA rules. Suppose that
you want to add a function to the `text` module that returns the N-th line in
the file.

Let's add a function called `get_line` to the `yara-x/src/modules/text.rs`
file. This function receives the line number and returns a string with the
corresponding line. Let's take a look at the implementation:

```rust
#[module_export]
fn get_line(ctx: &mut ScanContext, n: i64) -> Option<RuntimeString> {
    let cursor = io::Cursor::new(ctx.scanned_data());

    if let Some(Ok(line)) = cursor.lines().nth(n as usize) {
        Some(RuntimeString::from_slice(ctx, line))
    } else {
        None
    }
}
```

The first thing you may have noticed is that the function has the
`#[module_export]` attribute. This is how you indicate that your module exports
that function to YARA rules. The function will appear as a field of the `text`
module, and will have the same name as in the Rust code, so you can call it
from a YARA rule like `text.get_line(0)`.

The second important thing is that the function's first argument must be either
`&mut ScanContext` or `&ScanContext`. Of course this first argument won't be
part of the function's signature from the YARA rule standpoint. Any other
argument that you add to the function will be part of its signature when invoked
from YARA. In our example, the `n: i64` argument is where we pass the line
number to the function.

As types in YARA are limited to integers, floats, booleans and strings, the
types that you can use for function arguments or return types is limited to
a handful of Rust types. The following tables summarizes the accepted argument
and return types:

###### Valid function arguments

| Rust type       | YARA type |
|-----------------|-----------|
| `i32`           | integer   |
| `i64`           | integer   |
| `f32`           | float     |
| `f64`           | float     |
| `bool`          | bool      |
| `RuntimeString` | string    |

###### Valid return types

| Rust type               | YARA type                     |
|-------------------------|-------------------------------|
| `i32`                   | integer                       |
| `i64`                   | integer                       |
| `f32`                   | float                         |
| `f64`                   | float                         |
| `bool`                  | bool                          |
| `RuntimeString`         | string                        |
| `Option<i32>`           | integer / undefined if `None` |
| `Option<i64>`           | integer / undefined if `None` |
| `Option<f32>`           | float / undefined if `None`   |
| `Option<f64>`           | float  / undefined if `None`  |
| `Option<bool>`          | bool  / undefined if `None`   |
| `Option<RuntimeString>` | string / undefined if `None`  |

One noticeable difference between arguments and return types is that in return
types you can use `Option<T>`, where `T` is one of the acceptable Rust types.
When a function returns `None`, that's translated to `undefined` in YARA's
world.

Also notice that string types are always passed around in the form of a
`RuntimeString` instance, which represents an arbitrary sequence of bytes. The
standard Rust types (`String`, `&str`, `&[u8]`, etc) are not allowed. In the
next section were going to discuss more about how to receive and return strings
in module functions.

In our example, the `get_line` function is defined at the top level of the
module's namespace, which means that it will be invoked from YARA as
`text.get_line(..)`. But sometimes we want our function to appear as a member
of some inner structure. For example, suppose that we have a module with the
following structure:

```protobuf
message SomeStruct {
  optional int64 foo = 1;
  optional int64 bar = 2;
}

message MyModule {
  optional SomeStruct some_struct = 1;
}
```

Here `MyModule` is the module's root structure, and it has a
field `some_structure`
described by `SomeStruct`. What if you want a function `some_function` that
appears to be a member of `some_structure`? In other words, you want to invoke
your function in YARA like this...

```yara
import "my_module"

rule my_rule {
    condition:
        my_module.some_structure.some_function()
}
```

Well, in that case the function must be named explicitly, including in the
name the full path of the function relative to the module's main structure.
This is done by providing a `name` argument to the `module_export` attribute.
For example:

```rust
#[module_export(name = "some_structure.some_function")]
pub(crate) fn some_function(ctx: &mut ScanContext) {
    // ...  
}
```

When a `name` argument is passed to `module_export`, the function's name in Rust
is ignored, and the explicitly provided name is used instead. This name is the
full path of the function, relative to the module.

This mechanism for choosing the name of your function explicitly also comes
handy  
for function overloading (i.e: using the same name for functions that differ in
their signatures). For example, suppose that you want to implement a `add`
function that can receive either integer or floating point numbers. The Rust
language doesn't support function overloading, but you can provide two different
implementations and force them to have the same name in YARA.

```rust
#[module_export(name = "add")]
pub(crate) fn add_i64(ctx: &mut ScanContext, a: i64, b: i64) -> i64 {
    a + b
}

#[module_export(name = "add")]
pub(crate) fn add_f64(ctx: &mut ScanContext, a: f64, b: f64) -> f64 {
    a + b
}
```

## String types in module functions

When you want to receive an argument or return a value of type string you must
use the `RuntimeString` type. This type is an enum with three variants:

* `RuntimeString::Literal`
* `RuntimeString::ScannedDataSlice`
* `RuntimeString::Rc`

`RuntimeString::Literal` is used when the string is a literal in the YARA rule.
For example, if your rule uses the
expression `my_module.my_func("foo")`, `"foo"`
is a literal and the function `my_func` will receive a `RuntimeString::Literal`
argument. Instances of `RuntimeString::Literal` are normally created by YARA and
passed as arguments to functions. Functions won't return instances of
`RuntimeString::Literal` created by themselves.

`RuntimeString::ScannedDataSlice` represents a string that is a slice of the
scanned data. This variant is useful when you want to return some string that
is part of the scanned data, without having to make a copy of it. Internally,
this variant simply contains the offset within the data where the string starts
and its length, so it's a very similar to Rust slices.

`RuntimeString::Rc` is a reference-counted string that is released when all
references are dropped. This is the variant used when the string you are
returning from your function is not part of the scanned data, and therefore
needs to reside in its own memory.

Regardless of the variant, `RuntimeString` has a `as_bstr` method that allows
you to obtain a reference to the actual string. This method receives
a `&ScanContext`
and returns a `&BStr`. The `&BStr` type is equivalent to `&str`, but it doesn't
require that the string must be a valid UTF-8, as `&str` does. Aside from that,
`&BStr` behaves almost exactly to `&str` and has the same methods. You can find
more information in the documentation for
the [bstr](https://docs.rs/bstr/latest/bstr/)
crate.

For creating an instance of `RuntimeString` you must either
use `RuntimeString::new`
or `RuntimeString::from_slice`. `RuntimeString::new` creates the runtime string
by taking ownership of a `String`, `Vec<u8>`, or any type that implements
`Into<Vec<u8>`.

In the other hand, `RuntimeString::from_slice` receives a `&[u8]`
and creates the runtime string by making a copy of the slice, except if the
slice lies within the boundaries of the scanned data, in which case the returned
variant is `RuntimeString::ScannedDataSlice`.

```rust
/// A function that always returns the string "foo".
#[module_export]
fn foo(ctx: &mut ScanContext) -> RuntimeString {
    RuntimeString::from_slice("foo".as_bytes())
}
```

```rust
/// A function that receives a string and returns it in uppercase.
#[module_export]
fn uppercase(ctx: &mut ScanContext, s: RuntimeString) -> RuntimeString {
    // Obtain a &BStr pointing to the actual string content. 
    let s = s.as_bstr(ctx);
    // &BStr has the same methods than &str, including to_uppercase. 
    let s = s.to_uppercase();
    // Returns RuntimeString::Rc with the new string.
    RuntimeString::new(s)
}
```

```rust
/// A function that returns a string with the first n bytes of the scanned data.
///
/// If the data is smaller than n bytes the result will be `None`, which is
/// treated in YARA as `undefined`.
#[module_export]
fn head(ctx: &mut ScanContext, n: i64) -> Option<RuntimeString> {
    // Get the first n bytes, or return None.
    let head = ctx.scanned_data().get(0..n as usize)?;
    // Returns RuntimeString::ScannedDataSlice, as the `head` slice is contained
    // within the scanned data.
    Some(RuntimeString::from_slice(ctx, head))
}
```

## Accessing the module's structure from a function

When we
discussed [how to implement the module's main function](#implementing-the-modules-main-function),
we saw that this function returns a protobuf structure with information that
is usually extracted away from the data being scanned. The fields in this
structure can be used directly in your YARA rules, but sometimes we need to
use them from within module functions as well. This is useful for implementing
functions that rely on information that was already extracted from the scanned
data and stored in that protobuf message.

Let's go back to our `text` module example, which already exports two fields:
`num_lines` and `num_words`. Now suppose that you want to implement a function
`avg_words_per_line`, that returns the result of `num_words / num_lines`. Of
course, you could add a new field and initialize it with the correct value in
the main function, so this is not a very realistic example, but let's assume
that you don't want to resort to using a new field, but want a function instead.
How do you access the values of `num_words` and `num_lines` from the
`avg_words_per_line` function? Let's see it:

```rust
#[module_export]
fn avg_words_per_line(ctx: &mut ScanContext) -> Option<f64> {
    // Obtain a reference to the `Text` protobuf that was returned by the
    // module's main function.
    let text = ctx.module_output::<Text>()?;

    let num_lines = text.num_lines? as f64;
    let num_words = text.num_words? as f64;

    Some(num_words / num_lines)
}
```

The secret is in this line:

```rust
let text = ctx.module_output::<Text>() ?;
```

The `ScanContext` type has a `module_output` method that is generic over
type `T`,
while calling this method you must specify the type of the protobuf associated
to your module (`Text` in this case). This is done by using Rust's
[turbofish](https://www.youtube.com/watch?v=oQhYb7NgdUU) syntax
(i.e: `module_output::<T>()`). Notice that this method returns `Option<&T>`.

## Adding dependencies

Most of the time your module is going to depend on external crates. Let's say
we want to add a new feature to our `text` module that detects the language in
which the text is written. For that, we are going to rely on the existing crate
[lingua](https://docs.rs/lingua/1.4.0/lingua/).

The first step is adding the `lingua` to the `[dependencies]` section in
`yara-x/Cargo.toml`, as any other dependency for the project. For example:

```toml
[dependencies]
lingua = { version = "1.4.0", optional = true }
```

Notice the use `optional = true` for preventing this crate from being compiled
by default. We want to build the `lingua` crate only when the `text-module`
feature flag is set. This done by adding `"dep:lingua"` to the feature as
shown below.

```toml
[features]
text-module = ["dep:lingua"]
```

Now we can use the `lingua` crate in our `text` module, so let's add a function
for detecting the language:

```rust
use lingua::LanguageDetectorBuilder;

#[module_export]
fn language(ctx: &ScanContext) -> Option<i64> {
    let data = ctx.scanned_data();
    // Use `as_bstr()` for getting the scanned data as a `&BStr` instead of a
    // a `&[u8]`. Then call `to_str` for converting the `&BStr` to `&str`. This
    // operation can fail if the scanned data is not valid UTF-8, in that case
    // returns `None`, which is interpreted as `undefined` in YARA.
    let text = data.as_bstr().to_str().ok()?;

    // Configure the languages that we want to detect.
    let detector = LanguageDetectorBuilder::from_languages(&[
        lingua::Language::English,
        lingua::Language::French,
        lingua::Language::German,
        lingua::Language::Spanish,
    ])
        .build();

    // Detect the language. Returns `None` if the language cannot be reliably
    // detected.
    let language = detector.detect_language_of(text)?;

    // `language` is an enum that has only unit variants, it can be casted to
    // `i64` for getting the numeric value.
    Some(language as i64)
}
```

The code above has a problem, though. We are returning an `i64` where each
value represents a language, but writing YARA conditions like
`text.language() == 3` is not very readable. Which is language 3? This is
where enums come into play.

## Using enums

In the previous section we implemented the `language` function that returns a
numeric value indicating the language in which a text file is written. However,
using numeric literals like `1`, `2` or `3` for identifying languages is not
readable, it would be much better if we could associate those literals to more
descriptive symbols like `english`, `spanish` and `french`. In cases like this
enums are really useful. Let's add this enum definition to the `text.proto`
file:

```protobuf
enum Language {
  English = 1;
  Spanish = 2;
  French = 3;
  German = 4;
}
```

Now let's rewrite the `language` function:

```rust
#[module_export]
fn lang(ctx: &ScanContext) -> Option<i64> {
    let data = ctx.scanned_data();
    // Use `as_bstr()` for getting the scanned data as a `&BStr` instead of a
    // a `&[u8]`. Then call `to_str` for converting the `&BStr` to `&str`. This
    // operation can fail if the context is not valid UTF-8, in that case
    // returns `None`, which is interpreted as `undefined` in YARA.
    let text = data.as_bstr().to_str().ok()?;

    let detector = LanguageDetectorBuilder::from_languages(&[
        lingua::Language::English,
        lingua::Language::French,
        lingua::Language::German,
        lingua::Language::Spanish,
    ])
        .build();

    // Detect the language. Convert the result returned by `lingua` to our
    // own enum defined in the protobuf.
    let language = match detector.detect_language_of(text)? {
        lingua::Language::English => Language::English,
        lingua::Language::French => Language::French,
        lingua::Language::German => Language::German,
        lingua::Language::Spanish => Language::Spanish,
        _ => unreachable!(),
    };

    Some(language as i64)
}
```

In the snippet above, constants `Language::English`, `Language::French`,
`Language::German` and `Language::Spanish` are the ones defined in the
`text.proto` file. They are accessible in our code because of the
`use crate::modules::protos::text::*;` statement at the beginning of the source
file, which imports all the types defined by the protobuf.

Also notice how the `match` statement is converting the result returned by
the `lingua` crate, which is one of the values in the `lingua::Language` enum,
to our own enum. This is because relying on the actual numeric value associated
to each alternative in `lingua::Language` (the discriminant in Rust terms) is
not a good idea. If the developers of `lingua` alter the order in which the
languages appear in the `lingua::Language` enum, this would also change their
respective numeric values (or discriminant).

After this change we can write a YARA rule like:

```yara
import "text"

rule text_in_english {
    condition:
        text.language() == text.Language.English
}
```

In our example the values in the enum started at 1 and where consecutive. But
this is not a requirement, you can associate arbitrary values to each enum
item, and use hexadecimal numbers for better legibility. The following enum is
also valid:

```protobuf
enum Threshold {
  Low = 100;
  Medium = 400;
  High = 900;
}
```

However, because tag numbers are of type `i32`, the range of possible values
goes from `i32::MIN` to `i32::MAX`. For larger values you need to use an
alternative approach:

```protobuf
enum MachO {
  MAGIC = 0 [(yara.enum_value).i64 = 0xfeedface];
  CIGAM = 1 [(yara.enum_value).i64 = 0xcefaedfe];
}
```

In the enum above the values of `MAGIC` and `CIGAM` are not `0` and `1` but
`0xfeedface` and `0xcefaedfe` respectively. Tag numbers are still present
because they are required in protobuf, however, their values are irrelevant.
The `(yara.enum_value).i64` option has priority when assigning a value to each
enum item, and it allows setting values from `i64::MIN` to `i64::MAX`.

### Inline enums

As you may have noticed in the examples above, the name path for accessing some
enum value in your YARA rules includes the name of the enum itself. For
instance,
if you want to use the `Low` value from the `Threshold` enum, declared in some
`acme` module, you would write `acme.Threshold.Low`.

The recommended way for naming enums and is that the enum's name itself should
describe the whole class of values it contains, and items in the enum should
describe specific items (i.e: `acme.Threshold.Low` is preferred over
`acme.ThresholdLow` or `acme.Threshold_Low`). However, some existing YARA
modules
don't follow this guideline, and have a multiple groups of constants defined at
the module's top level. For example, the `macho` module contains, among others,
the following constants (their values are included for reference):

- `macho.CPU_TYPE_MC680X0` = 0x06
- `macho.CPU_TYPE_X86` = 0x07
- `macho.CPU_TYPE_ARM` = 0x0c
- `macho.CPU_SUBTYPE_386` = 0x03
- `macho.CPU_SUBTYPE_486` = 0x04
- `macho.CPU_SUBTYPE_586` = 0x05
- `macho.CPU_SUBTYPE_ARM_V4T` = 0x05
- `macho.CPU_SUBTYPE_ARM_V5` = 0x07
- `macho.CPU_SUBTYPE_ARM_V6` = 0x06

All these constants can't be put together in a single enum, as some of them
share the same value, (e.g: both `CPU_SUBTYPE_586` and `CPU_SUBTYPE_ARM_V4T`
are equal to `0x05`), and protobuf enums can't have duplicated values. The
solution could be grouping them in different enums, like for example:

```protobuf
enum CPU_TYPE {
  MC680X0 = 0x06;
  X86 = 0x007;
  ARM = 0x0c;
}

enum CPU_SUBTYPE_INTEL {
  I386 = 0x03;
  I486 = 0x04;
  I586 = 0x05;
}

enum CPU_SUBTYPE_ARM {
  V4T = 0x05;
  V5 = 0x07;
  V6 = 0x06;
}
```

The problem with this approach is that you would need use expressions like these
in your YARA rules:

- `macho.CPU_TYPE.ARM`
- `macho.CPU_SUBTYPE_ARM.V5`
- `macho.CPU_SUBTYPE_INTEL.I386`

This may be ok if you are writing a new module, but it's not enough if you are
porting an existing module like `macho`, where maintaining the same names for
constants is a must. What to do then? Inline enums comes to your rescue.

An inline enum is one that puts their items directly at the module's top level,
or the structure where the enum is declared, without introducing an additional
struct named after the enum itself. For instance:

```protobuf
enum CPU_TYPE {
  option (yara.enum_options).inline = true;
  CPU_TYPE_MC680X0 = 0x06;
  CPU_TYPE_X86 = 0x007;
  CPU_TYPE_ARM = 0x0c;
}

enum CPU_SUBTYPE_INTEL {
  option (yara.enum_options).inline = true;
  CPU_SUBTYPE_I386 = 0x03;
  CPU_SUBTYPE_I486 = 0x04;
  CPU_SUBTYPE_I586 = 0x05;
}

enum CPU_SUBTYPE_ARM {
  option (yara.enum_options).inline = true;
  CPU_SUBTYPE_V4T = 0x05;
  CPU_SUBTYPE_V5 = 0x07;
  CPU_SUBTYPE_V6 = 0x06;
}
```

With the enums above you can refer to `macho.CPU_TYPE_X86` and instead of
`macho.CPU_TYPE.CPU_TYPE_X86` and `macho.CPU_SUBTYPE_INTEL.CPU_SUBTYPE_I386`.

## Tests

You'll notice that each module in `/yara-x/src/modules/` has a `tests/`
directory with a nested `testdata/` directory. The testing framework is
expecting a particular format and input structure to use them:

1. File converted
   to [Intel Hex](https://developer.arm.com/documentation/ka003292/latest/)
   format format
2. Intel Hex format output zipped
3. End file named <sha_256>.in.zip

### Structuring Testdata Input

To convert the binary to Intel Hex format, we can use the various tools,
depending on the operating system.

To start, we need the raw binary with the sha256 of the binary as its
identifier. This can be done differently on various platforms. These steps
assume the binary is named its sha256 hash (`<sha256_hash>` is used as a
placeholder).

#### Linux

You can
leverage [objcopy](https://man7.org/linux/man-pages/man1/objcopy.1.html).

```bash
objcopy -I binary -O ihex <sha256_hash> <sha256_hash>.in
```

#### MacOS

You can
leverage [llvm-objcopy](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#supported-formats).

```bash
llvm-objcopy -I binary -O ihex <sha256_hash> <sha256_hash>.in
```

#### Other Operating Systems

If you cannot use `objcopy` or `llvm-objcopy` on your current OS, you can use
the provided scripts
at [python-intelhex/intelhex](https://github.com/python-intelhex/intelhex/),
assuming you can run Python.

```bash
bin2hex.py <sha256_hash> <sha256_hash>.in
```

#### Archiving the test data

You can then archive the file into a zip archive using an archival utility and
move it to the appropriate test directory. An example of that is below:

```bash
zip <sha256_hash>.in.zip <sha256_hash>.in
mv <sha256_hash>.in.zip <location_of_yara-x>/yara-x/src/modules/<module>/tests/testdata/
```

### Converting the Files back to Original Format

If you need the files back in binary form, you can inverse the steps above.

#### Unarchiving the test data

You can then unarchive the file using an archival utility. An example of that is
below:

```bash
unzip <sha256_hash>.in.zip
```

#### Linux

You can
leverage [objcopy](https://man7.org/linux/man-pages/man1/objcopy.1.html).

```bash
objcopy -I ihex -O binary <sha256_hash>.in <sha256_hash>
```

#### MacOS

You can
leverage [llvm-objcopy](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#supported-formats).

```bash
llvm-objcopy -I ihex -O binary <sha256_hash>.in <sha256_hash>
```

#### Other Operating Systems

If you cannot use `objcopy` or `llvm-objcopy` on your current OS, you can use
the provided scripts
at [python-intelhex/intelhex](https://github.com/python-intelhex/intelhex/),
assuming you can run Python.

```bash
hex2bin.py <sha256_hash>.in <sha256_hash>
```
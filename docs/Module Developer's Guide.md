Module Developer's Guide
========================

YARA modules are the way in which you can extend YARA's capabilities by 
adding new data structures and functions that can be later used in your rules, 
making them more powerful and expressive. For example, a YARA module can
parse a file format and expose to YARA any information extracted from the 
file that may be useful while creating YARA rules.

This document will guide you through the process of creating a YARA module. 
For illustrative purposes we are going to create a `csv` module that parses
[Comma-Separated Values](https://en.wikipedia.org/wiki/Comma-separated_values) 
(CSV) files.


* [Defining the module's structure](#defining-the-modules-structure)
* [Proto2 vs Proto3](#proto2-vs-proto3)
* [Defining the module's main function](#defining-the-modules-main-function)
* [Building your module](#building-your-module)


## Defining the module's structure

Most YARA modules define a data structure that is filled with information 
extracted from the scanned file and exposed to YARA with the purpose of being
used in your rules. In YARA-X this structure is defined by using 
[Protocol Buffers](https://developers.google.com/protocol-buffers) (protobuf 
from now on). The first thing you must do when creating your module is 
writing the protobuf that defines the module's structure. If you are not familiar
with protobufs we recommend you to start by exploring its documentation and 
getting used to its syntax. You don't need to become an expert in protobufs for
being able to define a YARA module, but some familiarity will certainly help.

Let's start defining the structure for our `csv` module. For that, you must 
create a `csv.proto` file and put it into the `yara-x/src/modules/protos`
directory. As a starting point we can use the following file:

```protobuf
syntax = "proto2";

import "YARA.proto";

option (YARA.module_options) = {
  name : "csv"
  root_message: "CSV"
  rust_module: "csv"
};

message CSV {
  optional int64 num_rows = 1;
  optional int64 num_cols = 2;
}
```

This is a very simple module that exposes only two fields: `num_rows` and 
`num_cols`. Let's dissect the content of `csv.proto` line by line:

```protobuf
syntax = "proto2";
```

This indicates which version of the protobuf syntax you are going to use. There
are two possibilities here: `proto2` and `proto3`. We are going to talk about 
the differences between the two in [Proto2 vs Proto3](#proto2-vs-proto3), but
for the time  being let's use `proto2`. By the way, `proto2` is the default 
if you don't specify the syntax version, which means that the first line in 
the file is  actually optional. However, we recommend making your choice 
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

Let's start with the interesting part:

```protobuf
option (yara.module_options) = {
  name : "csv"
  root_message: "CSV"
  rust_module: "csv"
};
```

The snippet above is also required for every `.proto` file that describes a 
YARA module. This is what tells that this file is not an ordinary `.proto` 
file, but one describing a module. In fact, you can put any `.proto` file in the
`yara-x/src/modules/protos` directory, and that doesn't mean that each of those 
files is describing a YARA module. Only files containing a `yara.module_options` 
section will define a module.

Options `name` and `root_message` are required, while `rust_module` is optional.
The `name` option defines the module's name. This is the name that will be used
for importing the module in a YARA rule, in this case our module will be imported
with `import "csv"`. The `root_message` option indicates which is the module's 
root structure, it must contain the name of some structure (a.k.a message) defined 
in the `.proto` file. In our case the value for `root_message` is `"CSV"` because
we have defined our module's structure in a message named `CSV`. This is required
because your `.proto` file can define multiple messages, and YARA needs to know
which of them considered the root message for the module.

And here is our root structure/message:

```protobuf
message CSV {
  optional int64 num_rows = 1;
  optional int64 num_cols = 2;
}
```

This is a very simple structure with only two integer fields. Notice that the
numbers after the `=` signs are not the values for those fields, they are 
actually field tags (i.e: a unique number identifying each field in a message).
This may be confusing for those of you who are not familiar with protobuf's
syntax, so again: explore the protobuf's 
[documentation](https://developers.google.com/protocol-buffers). 

Also notice that we are defining our fields as `optional`. In `proto2` fields
must be either `optional` or `required`, while in `proto3` they are always
optional and can't be forced to be required. We are going to discuss this topic
more in-depth in the [Proto2 vs Proto3](#proto2-vs-proto3) section.

With this we have defined a very simple module that could be used in a YARA
rule like this:

```yara
import "csv"

rule csv_with_two_columns_and_many_rows {
    condition:
        csv.num_cols == 2 and csv.num_rows > 100
}
```

Of course, we are not done yet. So far we have defined the structure of our
module, but we need to populate that structure with actual values extracted from
the scanned files. That's where the module's main function enters into play. But
before going into the details of how to implement this function, let's discuss 
first the differences between `proto2` and `proto3`, as they may determine some 
aspects of our implementation.

## Proto2 vs Proto3

When writing a YARA module you can choose between `proto2` and `proto3` for
writing the protobuf that describes your module's structure. Both of them
are very similar, but they also have significant differences.

One of the most important differences is that in `proto2` fields are either
`optional` or `required`, while in `proto3` all fields are optional, and therefore
the keywords `optional` and `required` are not accepted at all. But this difference
goes beyond a simple syntactic matter, it also affects the way in which missing
fields are handled.

In `proto2` when some structure contains a `required` field, this field must
be initialized to some value before the structure gets serialized. If you don't
provide a value for a `required` field, an error occurs while serializing the
structure. In the other hand, `optional` fields don't need to be initialized,
they simply won't be included in the serialized data, and they will be missing
after the data is deserialized. In fact, if you have a field `optional int64 foo`
in your protobuf, the corresponding Rust structure will have a field
`foo: Option<i64>`. If `foo` is not initialized, its value after deserializing
the structure will be `None`. This means that in `proto2` you can know whether
the field `foo` was originally initialized to some value, or it was simply left
uninitialized.

In `proto3` things are a bit different. All fields in `proto3` are optional,
but uninitialized fields will have a default value that depends on the type.
For example, for numeric fields the default value is zero, and for string fields
the default value is the empty string. This means that in `proto3` a protobuf
field `int64 foo` is translated into a field `foo: i64`. If `foo` is not
initialized, it will behave as it was initialized to 0. After deserializing
your structure, you won't be able to tell if `foo` was explicitly set to 0,
or if it was left uninitialized.

This subtle difference is important when creating a YARA module, because 
YARA has the concept of `undefined` values. A value in YARA is `undefined` when 
it hasn't been initialized to some meaningful value. When `proto2` is used for
defining the structure of your module, uninitialized fields will have an
`undefined` value. In the other hand, when `proto3` is used  all fields will
have a value, even if you don't initialize it explicitly. If a field is not
initialized it will have its corresponding default value.

The bottom line is that with `proto3` you won't be able to have fields with
`undefined` values. In some cases that may be what you need, and using `proto3`
is very useful in such cases, as you don't need to explicitly initialize all
the fields in your structure.

## Defining the module's main function

Once you have a `.proto` file that describes the structure of your module you
need write the logic that parses every scanned file and fills the module's
structure with the data obtained from the file. This is done by implementing
a function that will act as the entry point for your module.

This is where the `rust_module` option described in the previous section enters 
into play. This option is the name of the Rust module that contains the code 
for your module. In our `csv.proto` file we have `rust_module: "csv"`, which 
means that our Rust module must be named `csv`.

There are two options for creating our `csv` module:

* Creating a `csv.rs` file in `yara-x/src/modules`.
* Creating a directory `yara-x/src/modules/csv` containing a`mod.rs` file.

For simple modules that can be contained in a single `.rs` file the first 
approach is enough. For more complex modules with multiple source files the 
second approach is the recommended one.

So, let's create our `yara-x/src/modules/csv.rs` file:

```rust
use crate::modules::prelude::*;
use crate::modules::protos::csv::*;

#[module_main]
fn main(ctx: &ScanContext) -> CSV {
    let mut csv_proto = CSV::new();
    let data = ctx.scanned_data();

    // TODO: parse the scanned data and populate csv_proto.

    csv_proto
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
use crate::modules::protos::csv::*;
```

Here we are importing all the Rust types automatically generated from our
`csv.proto` file. This includes the `CSV` structure, which represents the `CSV` 
message declared in the proto file. 

---

**NOTE**: If your protobuf file is `foobar.proto`, the module created for it 
will be `crate::modules::protos::foobar`

---

Next comes the module's main function:

```rust
#[module_main]
fn main(ctx: &ScanContext) -> CSV { 
    ...
}
```

The module's main function is called for every file scanned by YARA. This 
function receives a reference to a `ScanContext` structure that gives you access
to the scanned data, as we will show later. It must return the `CSV` structure 
that was generated from the `csv.proto` file. The main function must have the 
`#[module_main]` attribute. Notice that the module's main function doesn't need 
to be called `main`, it can have any arbitrary name, as long as it has the 
`#[module_main]` attribute. Of course, this attribute can't be used with more 
than one function per module.

The main function usually consists in creating an instance of the protobuf 
returned by the module, and then populate and return that proto.

After defining the module's structure, and providing the main function for our
module, we are ready to build the module into YARA.

## Building your module

After creating the files `yara-x/src/modules/protos/csv.proto` and 
`yara-x/src/modules/csv.rs` we are almost ready for building the module into 
YARA. But there are few more pending steps.

Ths first thing that you must know is that your module is behind a `cargo` feature
flag. The module won't be built into YARA unless you tell `cargo` to do so. The 
name of the feature controlling your module is `csv-module`, and this feature 
must be added to the `[features]` section in the `yara-x/Cargo.toml` file.

```
[features]
csv-module = []  # Add this line to yara-x/Cargo.toml
```

Additionally, if you want your module to be included by default in YARA, add
the feature name to the `default` list in the `[features]` section of
`yara-x/Cargo.toml`:


```
[features]
csv-module = []

# Features that are enabled by default.
default = [
    "compile-time-optimization",
    "test_proto2-module",
    "test_proto3-module",
    "csv-module"             # The csv module will be included by default
]
```

If the module's feature flag is not added to the `default` list, you must
explicitly tell `cargo` that you want to build YARA with your module:

```shell
cargo build --features=csv-module
```

---

**NOTE**: The name of the feature flag depends on the module's name. If the 
module's name is `foobar`, the feature flag is `foobar-module`.

---


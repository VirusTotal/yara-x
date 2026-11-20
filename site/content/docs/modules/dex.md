---
title: "dex"
description: ""
summary: ""
date: 2025-09-24T16:00:00:00+00:00
lastmod: 2025-09-24T16:00:00:00+00:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "dex-module"
weight: 400
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `dex` module exposes most of the fields present in a DEX file.
Let's see some examples:

```yara
import "dex"

rule check_dex_version {
    condition:
        dex.header.version == 41
}

rule search_string {
    condition:
        for any string in dex.string_ids: (
            string == "Landroid/content/ComponentName;"
        )
}
```

---

## Functions

### checksum()

Counts the Adler-32 checksum of the DEX file.

#### Example

```yara
import "dex"

rule invalid_checksum {
    condition:
        dex.header.checksum != dex.checksum()
}
```

### signature()

Return the SHA-1 signature of the DEX file.

#### Example

```yara
import "dex"

rule invalid_signature {
    condition:
        dex.header.signature != dex.signature()
}
```

### has_string()

String search using binary search. Useful for very large number of strings.
Also available under the alias `contains_string()`.

#### Example

```yara
import "dex"

rule search_string {
    condition:
        dex.has_string("Landroid/content/ComponentName;")
}
```

### has_method()

Returns true if the DEX file contains a method matching the given criteria.
Also available under the alias `contains_method()`. The function is overloaded
and accepts:

- `has_method(method_name)` — a method whose name equals `method_name`.
- `has_method(/method_name/)` — a method whose name matches the regular
  expression.
- `has_method(class_name, method_name)` — a method named `method_name`
  belonging to the class `class_name`.
- `has_method(/class_name/, /method_name/)` — the regular-expression form of
  the above.

All comparisons are case-sensitive.

#### Example

```yara
import "dex"

rule search_method {
    condition:
        dex.has_method("<init>") and
        dex.has_method(/^get/) and
        dex.has_method("Landroid/app/Application;", "onCreate")
}
```

### has_class()

Returns true if the DEX file defines a class matching the given criteria. Also
available under the alias `contains_class()`. The function is overloaded and
accepts:

- `has_class(class_name)` — a defined class whose name equals `class_name`.
- `has_class(/class_name/)` — a defined class whose name matches the regular
  expression.

The comparison is case-sensitive.

#### Example

```yara
import "dex"

rule search_class {
    condition:
        dex.has_class("Landroid/content/Context;") and
        dex.has_class(/^Landroid\//)
}
```

---

## Module structure

| Field      | Type                                        | Description                                    |
|------------|---------------------------------------------|------------------------------------------------|
| is_dex     | bool                                        | True if the file is DEX                        |
| header     | [DexHeader](#dexheader)                     | DexHeader                                      |
| strings    | string array                                | List of defined strings                        |
| types      | string array                                | List of defined types                          |
| protos     | [ProtoItem](#protoitem) array               | List of defined prototypes                     |
| fields     | [FieldItem](#fielditem) array               | List of defined fields                         |
| methods    | [MethodItem](#methoditem) array             | List of defined methods                        |
| class_defs | [ClassItem](#classitem) array               | List of defined classes                        |
| map_list   | [MapList](#maplist)                         | List of the entire contnts of a file, in order |

### DexHeader

Read more about it in [dex-format](https://source.android.com/docs/core/runtime/dex-format#appears-in-the-header-section).

| Field           | Type    | Description                                                                                   |
| --------------- | ------- | --------------------------------------------------------------------------------------------- |
| magic           | integer | DEX magic `0x6465780a`                                                                        |
| version         | integer | DEX version: 35, 36, 37, 38, 39, 40, 41                                                       |
| checksum        | integer | Adler-32 checksum of the DEX file                                                             |
| signature       | string  | SHA-1 signature of the DEX file                                                               |
| file_size       | integer | Size of the entire file (including the header)                                                |
| header_size     | integer | Size of the header                                                                            |
| endian_tag      | integer | Endianness tag                                                                                |
| link_size       | integer | Size of the link section, or 0 if this file isn't statically linked                           |
| link_off        | integer | Offset from the start of the file to the link section, or 0 if `link_size == 0`               |
| data_size       | integer | Size of `data` section (only in v40 or earlier)                                               |
| data_off        | integer | Offset from the start of the file to the start of the `data` section (only in v40 or earlier) |
| container_size  | integer | Size of the entire file (only in v41 or later)                                                |
| header_offset   | integer | Offset from the start of the file to the start of this header (only in v41 or later)          |

### ProtoItem

| Field            | Type         | Description                  |
| ---------------- | ------------ | ---------------------------- |
| shorty           | string       | Short-form descriptor string |
| return_type      | string       | Return type string           |
| parameters_count | integer      | Number of parameters         |
| parameters       | string array | List of parameters           |

### FieldItem

| Field | Type   | Description                                      |
| ----- | ------ | ------------------------------------------------ |
| class | string | The name of the class to which the field belongs |
| type  | string | Field type                                       |
| name  | string | Field name                                       |

### MethodItem

| Field | Type                    | Description                                       |
| ----- | ----------------------- | ------------------------------------------------- |
| class | string                  | The name of the class to which the method belongs |
| proto | [ProtoItem](#protoitem) | Method prototype                                  |
| name  | string                  | Method name                                       |

### ClassItem

| Field       | Type                      | Description             |
| ----------- | ------------------------- | ----------------------- |
| class       | string                    | Class name              |
| access_flag | [AccessFlag](#accessflag) | Access flags            |
| superclass  | string                    | Superclass name         |
| source_file | string                    | Name of the source file |

### MapList

| Field | Type                      | Description          |
| ----- | ------------------------- | -------------------- |
| size  | integer                   | Size of the list     |
| items | [MapItem](#mapitem) array | Elements of the list |

### MapItem

| Field  | Type                  | Description                                    |
| ------ | --------------------- | ---------------------------------------------- |
| type   | [TypeCode](#typecode) | Type of the items                              |
| unused | integer               | Unused field                                   |
| size   | integer               | Count of the number of items                   |
| offset | integer               | Offset from the start of the file to the items |

### AccessFlag

| Field                     | Number    | Description                                                                                                      |
| ------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------- |
| ACC_PUBLIC                | `0x1`     | public: visible everywhere (class, field, method)                                                                |
| ACC_PRIVATE               | `0x2`     | private: only visible to defining class (class, field, method)                                                   |
| ACC_PROTECTED             | `0x4`     | protected: visible to package and subclasses (class, field, method)                                              |
| ACC_STATIC                | `0x8`     | static — class: not constructed with outer `this`; field: global to defining class; method: does not take `this` |
| ACC_FINAL                 | `0x10`    | final — class: not subclassable; field: immutable after construction; method: not overridable                    |
| ACC_SYNCHRONIZED          | `0x20`    | synchronized: method lock acquired automatically on call. Only valid with ACC_NATIVE                             |
| ACC_BRIDGE                | `0x40`    | bridge: compiler-generated type-safe bridge method                                                               |
| ACC_VARARGS               | `0x80`    | varargs: last argument is treated as a "rest" parameter                                                          |
| ACC_NATIVE                | `0x100`   | native: method implemented in native code                                                                        |
| ACC_INTERFACE             | `0x200`   | interface: multiply-implementable abstract class                                                                 |
| ACC_ABSTRACT              | `0x400`   | abstract — class: not directly instantiable; method: unimplemented in this class                                 |
| ACC_STRICT                | `0x800`   | strictfp: strict floating-point arithmetic rules                                                                 |
| ACC_SYNTHETIC             | `0x1000`  | synthetic: not directly defined in source code (class, field, method)                                            |
| ACC_ANNOTATION            | `0x2000`  | annotation: declared as an annotation class                                                                      |
| ACC_ENUM                  | `0x4000`  | enum — class: declared as an enum type; field: declared as enum value                                            |
| ACC_CONSTRUCTOR           | `0x10000` | constructor: class or instance initializer method                                                                |
| ACC_DECLARED_SYNCHRONIZED | `0x20000` | declared synchronized: method marked with `synchronized` keyword                                                 |

### AccessFlagSpecial

| Field         | Number | Description                                              |
| ------------- | ------ | -------------------------------------------------------- |
| ACC_VOLATILE  | `0x40` | volatile (field): special access rules for thread safety |
| ACC_TRANSIENT | `0x80` | transient (field): not saved by default serialization    |

### TypeCode

| Field                           | Number   |
| ------------------------------- | -------- |
| TYPE_HEADER_ITEM                | `0x0000` |
| TYPE_STRING_ID_ITEM             | `0x0001` |
| TYPE_TYPE_ID_ITEM               | `0x0002` |
| TYPE_PROTO_ID_ITEM              | `0x0003` |
| TYPE_FIELD_ID_ITEM              | `0x0004` |
| TYPE_METHOD_ID_ITEM             | `0x0005` |
| TYPE_CLASS_DEF_ITEM             | `0x0006` |
| TYPE_CALL_SITE_ID_ITEM          | `0x0007` |
| TYPE_METHOD_HANDLE_ITEM         | `0x0008` |
| TYPE_MAP_LIST                   | `0x1000` |
| TYPE_TYPE_LIST                  | `0x1001` |
| TYPE_ANNOTATION_SET_REF_LIST    | `0x1002` |
| TYPE_ANNOTATION_SET_ITEM        | `0x1003` |
| TYPE_CLASS_DATA_ITEM            | `0x2000` |
| TYPE_CODE_ITEM                  | `0x2001` |
| TYPE_STRING_DATA_ITEM           | `0x2002` |
| TYPE_DEBUG_INFO_ITEM            | `0x2003` |
| TYPE_ANNOTATION_ITEM            | `0x2004` |
| TYPE_ENCODED_ARRAY_ITEM         | `0x2005` |
| TYPE_ANNOTATIONS_DIRECTORY_ITEM | `0x2006` |
| TYPE_HIDDENAPI_CLASS_DATA_ITEM  | `0xF000` |

use lazy_static::lazy_static;
use protobuf::reflect::FileDescriptor;
use std::collections::HashMap;

pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

include!("modules.rs");

/// Type of module's main function.
type MainFn = fn(u32) -> u32;

/// Describes a YARA module.
pub struct Module<'a> {
    /// Pointer to the module's main function.
    main_fn: Option<MainFn>,
    /// A [`FileDescriptor`] for the protobuf that describes the module's
    /// structure. This allows iterating the fields declared by the module
    /// and obtaining their names and types.
    descriptor: &'a FileDescriptor,
}

/// Macro that adds a module to the `BUILTIN_MODULES` map.
///
/// # Example
///
/// include_module!(modules, "test", test, Some(test::main as MainFn));
///
macro_rules! add_module {
    ($modules_map:expr, $name:literal, $proto:ident, $main_fn:expr) => {{
        $modules_map.insert(
            $name,
            Module {
                main_fn: $main_fn,
                descriptor: protos::$proto::file_descriptor(),
            },
        );
    }};
}

lazy_static! {
    /// `BUILTIN_MODULES` is a static, global map where keys are module names
    /// and values are [`Module`] structures that describe a YARA module.
    ///
    /// This table is populated with the modules defined by a `.proto` file in
    /// `src/modules/protos`. Each `.proto` file that contains a statement like
    /// the following one defines a YARA module:
    ///
    /// option (yara.module_options) = {
    ///   name : "foo"
    ///   root_message: "Foo"
    ///   rust_module: "foo"
    /// };
    ///
    /// The `name` field is the module's name (i.e: the name used in `import`
    /// statements), which is also the key in `BUILTIN_MODULES`. `root_message`
    /// is the name of the message that describes the module's structure. This
    /// is required because a `.proto` file can define more than one message.
    ///
    /// `rust_module` is the name of the Rust module where functions exported
    /// by the YARA module are defined. This field is optional, if not provided
    /// the module is considered a data-only module.
    pub(crate) static ref BUILTIN_MODULES: HashMap<&'static str, Module<'static>> = {
        let mut modules = HashMap::new();
        // The modules.rs file is automatically generated at compile time by
        // build.rs. This is an example of how modules.rs looks like:
        //
        // {
        //  #[cfg(feature = "pe_module")]
        //  add_module!(modules, "pe", pe, Some(pe::main as MainFn));
        //
        //  #[cfg(feature = "elf_module")]
        //  add_module!(modules, "elf", elf, Some(elf::main as MainFn));
        // }
        //
        // modules.rs will contain an `add_module!` statement for each
        // protobuf in src/modules/protos defining a YARA module.
        include!(concat!(env!("OUT_DIR"), "/modules.rs"));

        modules
    };
}

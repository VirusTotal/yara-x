use protobuf::MessageDyn;
use protobuf::reflect::MessageDescriptor;
use rustc_hash::FxHashMap;
use thiserror::Error;

pub mod protos {
    #[cfg(feature = "generate-proto-code")]
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

    #[cfg(not(feature = "generate-proto-code"))]
    include!("protos/generated/mod.rs");
}

#[cfg(test)]
mod tests;

pub(crate) mod field_docs;
pub(crate) mod utils;

include!("modules.rs");

/// Enum describing errors occurred in modules.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ModuleError {
    /// Invalid format of module metadata.
    #[error("invalid metadata: {err}")]
    MetadataError {
        /// The error that actually occurred.
        err: String,
    },
    /// Error occurred when processing the input data.
    #[error("internal error: {err}")]
    InternalError {
        /// The error that actually occurred.
        err: String,
    },
}

/// Context passed to the main function of YARA modules.
#[derive(Default)]
pub struct ModuleContext<'a> {
    module_metadata: FxHashMap<&'static str, &'a [u8]>,
    #[cfg(any(feature = "zip-module", feature = "vba-module"))]
    pub(crate) zip_cache: Option<utils::zip::ZipCache<'a>>,
}

impl<'a> ModuleContext<'a> {
    /// Set the metadata associated to the module with the given name.
    pub fn set_module_metadata(
        &mut self,
        module_name: &'static str,
        metadata: &'a [u8],
    ) {
        self.module_metadata.insert(module_name, metadata);
    }

    /// Returns the metadata explicitly provided to the module with the given
    /// name, if any.
    pub fn get_module_metadata(&self, module_name: &str) -> Option<&[u8]> {
        self.module_metadata.get(module_name).copied()
    }
}

/// The trait implemented by all registered modules.
pub trait RegisteredModule: Send + Sync {
    /// Name used for the module in `import` statements (e.g. `"my_module"`).
    fn name(&self) -> &'static str;

    /// Returns the descriptor of the protobuf message that defines the
    /// module's root structure.
    fn root_descriptor(&self) -> MessageDescriptor;

    /// Main function called every time YARA scans some data, before
    /// evaluating the rules. Set to `None` for data-only modules.
    fn main_fn<'a>(
        &self,
        ctx: &mut ModuleContext<'a>,
        data: &'a [u8],
    ) -> Option<Result<Box<dyn MessageDyn>, ModuleError>>;

    /// Rust module path of the submodule inside the external crate that
    /// contains functions registered with `#[module_export(yara_x_crate = ...)]`.
    ///
    /// Must match the value that `module_path!()` expands to at those
    /// functions' definition site (e.g. `"my_crate::my_mod"`). Set to
    /// `None` for data-only modules that export no callable functions.
    fn rust_module_name(&self) -> Option<&'static str>;
}

pub type ModuleMainFn<T> =
    for<'a> fn(&mut ModuleContext<'a>, &'a [u8]) -> Result<T, ModuleError>;

/// Description of a YARA module, generic over the type `T` returned by the
/// main function.
pub struct Module<T>
where
    T: protobuf::MessageFull + 'static,
{
    /// Name used for the module in `import` statements (e.g. `"my_module"`).
    pub name: &'static str,
    /// Main function called every time YARA scans some data, before
    /// evaluating the rules. Set to `None` for data-only modules.
    pub main_fn: Option<ModuleMainFn<T>>,
    /// Rust module path of the submodule inside the external crate that
    /// contains functions registered with `#[module_export(yara_x_crate = ...)]`.
    pub rust_module_name: Option<&'static str>,
}

impl<T> RegisteredModule for Module<T>
where
    T: protobuf::MessageFull + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn root_descriptor(&self) -> MessageDescriptor {
        T::descriptor()
    }

    fn main_fn<'a>(
        &self,
        ctx: &mut ModuleContext<'a>,
        data: &'a [u8],
    ) -> Option<Result<Box<dyn MessageDyn>, ModuleError>> {
        self.main_fn.map(|f| {
            f(ctx, data).map(|ok| Box::new(ok) as Box<dyn MessageDyn>)
        })
    }

    fn rust_module_name(&self) -> Option<&'static str> {
        self.rust_module_name
    }
}

/// Macro used to register a YARA module.
///
/// # Examples
///
/// Registering a module with a main function:
///
/// ```ignore
/// register_module!("my_module", MyModuleProto, main);
/// ```
///
/// Registering a data-only module with no main function:
///
/// ```ignore
/// register_module!("my_module", MyModuleProto);
/// ```
#[macro_export]
macro_rules! register_module {
    ($name:literal, $root_message:ty, $main_fn:path) => {
        $crate::mods::prelude::inventory::submit! {
            &$crate::mods::prelude::Module::<$root_message> {
                name: $name,
                main_fn: Some($main_fn),
                rust_module_name: Some(module_path!()),
            } as &dyn $crate::mods::prelude::RegisteredModule
        }
    };
    ($name:literal, $root_message:ty) => {
        $crate::mods::prelude::inventory::submit! {
            &$crate::mods::prelude::Module::<$root_message> {
                name: $name,
                main_fn: None,
                rust_module_name: None,
            } as &dyn $crate::mods::prelude::RegisteredModule
        }
    };
}

inventory::collect!(&'static dyn RegisteredModule);

/// Returns an iterator over all registered modules.
#[inline]
pub(crate) fn registered_modules()
-> impl Iterator<Item = &'static dyn RegisteredModule> {
    inventory::iter::<&'static dyn RegisteredModule>().copied()
}

/// Returns a registered module given its name.
#[inline]
pub(crate) fn module_by_name(
    name: &str,
) -> Option<&'static dyn RegisteredModule> {
    registered_modules().find(|m| m.name() == name)
}

pub mod mods {
    /*! Utility functions and structures that allow invoking YARA modules directly.

    The utility functions [`invoke`], [`invoke_dyn`] and [`invoke_all`]
    allow leveraging YARA modules for parsing some file formats independently
    of any YARA rule. With these functions you can pass arbitrary data to a
    YARA module and obtain the same data structure that is accessible to YARA
    rules and which you use in your rule conditions.

    This allows external projects to benefit from YARA's file-parsing
    capabilities for their own purposes.

    # Example

    ```rust
    # use yara_x;
    let pe_info = yara_x::mods::invoke::<yara_x::mods::PE>(&[]);
    ```
    */

    /// Data structures defined by the `crx` module.
    ///
    /// The main structure produced by the module is [`crx::Crx`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::crx;
    /// Data structure returned by the `crx` module.
    pub use super::protos::crx::Crx;
    /// Data structures defined by the `dex` module.
    ///
    /// The main structure produced by the module is [`dex::Dex`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::dex;
    /// Data structure returned by the `dex` module.
    pub use super::protos::dex::Dex;
    /// Data structures defined by the `dotnet` module.
    ///
    /// The main structure produced by the module is [`dotnet::Dotnet`]. The
    /// rest of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::dotnet;
    /// Data structure returned by the `dotnet` module.
    pub use super::protos::dotnet::Dotnet;
    /// Data structures defined by the `elf` module.
    ///
    /// The main structure produced by the module is [`elf::ELF`]. The rest of
    /// them are used by one or more fields in the main structure.
    ///
    pub use super::protos::elf;
    /// Data structure returned by the `elf` module.
    pub use super::protos::elf::ELF;
    /// Data structures defined by the `lnk` module.
    ///
    /// The main structure produced by the module is [`lnk::Lnk`]. The rest of
    /// them are used by one or more fields in the main structure.
    ///
    pub use super::protos::lnk;
    /// Data structure returned by the `lnk` module.
    pub use super::protos::lnk::Lnk;

    /// Data structures defined by the `macho` module.
    ///
    /// The main structure produced by the module is [`macho::Macho`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::macho;
    /// Data structure returned by the `macho` module.
    pub use super::protos::macho::Macho;

    /// Data structures defined by the `olecf` module.
    ///
    /// The main structure produced by the module is [`olecf:Olecf`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::olecf;
    /// Data structure returned by the `olecf` module.
    pub use super::protos::olecf::Olecf;

    /// Data structures defined by the `vba` module.
    ///
    /// The main structure produced by the module is [`vba::Vba`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::vba;
    /// Data structure returned by the `macho` module.
    pub use super::protos::vba::Vba;

    /// Data structures defined by the `pe` module.
    ///
    /// The main structure produced by the module is [`pe::PE`]. The rest
    /// of them are used by one or more fields in the main structure.
    ///
    pub use super::protos::pe;
    /// Data structure returned by the `pe` module.
    pub use super::protos::pe::PE;

    /// A data structure containing the data returned by all modules.
    pub use super::protos::mods::Modules;

    /// Invokes a YARA module with arbitrary data.
    ///
    /// <br>
    ///
    /// YARA modules typically parse specific file formats, returning structures
    /// that contain information about the file. These structures are used in YARA
    /// rules for expressing powerful and rich conditions. However, being able to
    /// access this information outside YARA rules can also be beneficial.
    ///
    /// <br>
    ///
    /// This function allows the direct invocation of a YARA module for parsing
    /// arbitrary data. It returns the structure produced by the module, which
    /// depends upon the invoked module. The result will be [`None`] if the
    /// module does not exist, or if it doesn't produce any information for
    /// the input data.
    ///
    /// `T` must be one of the structure types returned by a YARA module, which
    /// are defined in [`crate::mods`], like [`crate::mods::PE`], [`crate::mods::ELF`], etc.
    ///
    /// # Example
    /// ```rust
    /// # use yara_x;
    /// let elf_info = yara_x::mods::invoke::<yara_x::mods::ELF>(&[]);
    /// ```
    pub fn invoke<T: protobuf::MessageFull>(data: &[u8]) -> Option<Box<T>> {
        let module_output = invoke_dyn::<T>(data)?;
        Some(<dyn protobuf::MessageDyn>::downcast_box(module_output).unwrap())
    }

    /// Like [`invoke`], but allows passing metadata to the module.
    pub fn invoke_with_meta<T: protobuf::MessageFull>(
        data: &[u8],
        meta: Option<&[u8]>,
    ) -> Option<Box<T>> {
        let module_output = invoke_with_meta_dyn::<T>(data, meta)?;
        Some(<dyn protobuf::MessageDyn>::downcast_box(module_output).unwrap())
    }

    /// Invokes a YARA module with arbitrary data, returning a dynamic
    /// structure.
    ///
    /// This function is similar to [`invoke`] but its result is a dynamic-
    /// dispatch version of the structure returned by the YARA module.
    pub fn invoke_dyn<T: protobuf::MessageFull>(
        data: &[u8],
    ) -> Option<Box<dyn protobuf::MessageDyn>> {
        invoke_with_meta_dyn::<T>(data, None)
    }

    /// Like [`invoke_dyn`], but allows passing metadata to the module.
    pub fn invoke_with_meta_dyn<T: protobuf::MessageFull>(
        data: &[u8],
        meta: Option<&[u8]>,
    ) -> Option<Box<dyn protobuf::MessageDyn>> {
        let descriptor = T::descriptor();
        let proto_name = descriptor.full_name();

        let module = super::registered_modules()
            .find(|m| m.root_descriptor().full_name() == proto_name)?;

        let mut ctx = super::ModuleContext::default();

        if let Some(m) = meta {
            ctx.module_metadata.insert(module.name(), m);
        }

        module.main_fn(&mut ctx, data)?.ok()
    }

    /// Invokes all YARA modules and returns the data produced by them.
    ///
    /// This function is similar to [`invoke`], but it returns the
    /// information produced by all modules at once.
    ///
    /// # Example
    /// ```rust
    /// # use yara_x;
    /// let modules_output = yara_x::mods::invoke_all(&[]);
    /// ```
    pub fn invoke_all(data: &[u8]) -> Box<Modules> {
        let mut info = Box::new(Modules::new());
        info.pe = protobuf::MessageField(invoke::<PE>(data));
        info.elf = protobuf::MessageField(invoke::<ELF>(data));
        info.dotnet = protobuf::MessageField(invoke::<Dotnet>(data));
        info.macho = protobuf::MessageField(invoke::<Macho>(data));
        info.lnk = protobuf::MessageField(invoke::<Lnk>(data));
        info.olecf = protobuf::MessageField(invoke::<Olecf>(data));
        info.vba = protobuf::MessageField(invoke::<Vba>(data));
        info.crx = protobuf::MessageField(invoke::<Crx>(data));
        info.dex = protobuf::MessageField(invoke::<Dex>(data));
        info
    }

    /// Iterator over all registered module names.
    ///
    /// See the "debug modules" command.
    pub fn module_names() -> impl Iterator<Item = &'static str> {
        use itertools::Itertools;
        super::registered_modules().map(|m| m.name()).sorted()
    }

    /// Returns the definition of the module with the given name.
    pub fn module_definition(name: &str) -> Option<reflect::Struct> {
        use std::rc::Rc;
        super::module_by_name(name)
            .map(|m| reflect::Struct::new(Rc::<crate::types::Struct>::from(m)))
    }

    /// Everything needed to implement your own YARA-X modules.
    #[allow(unused_imports)]
    #[allow(missing_docs)]
    pub mod prelude {
        pub use crate::modules::Module;
        pub use crate::modules::ModuleContext;
        pub use crate::modules::ModuleError;
        pub use crate::modules::RegisteredModule;
        pub use crate::register_module;
        pub use crate::wasm::runtime::Caller;
        pub use crate::wasm::string::FixedLenString;
        pub use crate::wasm::string::RuntimeString;
        pub use crate::wasm::string::String as _;
        pub use crate::wasm::string::{Lowercase, Uppercase};
        pub use crate::wasm::*;
        pub use bstr::ByteSlice;
        pub use inventory;
        pub use protobuf::MessageFull;
        pub use yara_x_macros::wasm_export;

        /// Opaque scan context passed as first argument to functions exported from a
        /// [`Module`] via `#[module_export]`.
        ///
        /// Functions only receive a reference to it; all fields are private.
        pub type ScanContext<'r, 'd> = crate::scanner::ScanContext<'r, 'd>;

        /// Attribute macro for exporting a callable function from a [`Module`].
        ///
        /// ```ignore
        /// use yara_x::mods::prelude::*;
        /// #[module_export]
        /// fn add(_ctx: &ScanContext, a: i64, b: i64) -> i64 { a + b }
        /// ```
        pub use yara_x_macros::module_export;
    }

    /// Types that allow for module introspection.
    ///
    /// This API is unstable and not ready for public use.
    #[doc(hidden)]
    pub mod reflect {
        use std::borrow::Cow;
        use std::rc::Rc;

        use crate::types;
        use crate::types::{Map, TypeValue};

        /// Describes a structure or module.
        #[derive(Clone, Debug, PartialEq)]
        pub struct Struct {
            inner: Rc<types::Struct>,
        }

        impl Struct {
            pub(super) fn new(inner: Rc<types::Struct>) -> Self {
                Self { inner }
            }

            /// Returns an iterator over the fields defined in the structure.
            ///
            /// The fields are sorted by name.
            pub fn fields(&self) -> impl Iterator<Item = Field<'_>> + '_ {
                self.inner
                    .fields()
                    .map(|(name, field)| Field::new(name, field))
            }
        }

        /// Describes a function.
        #[derive(Clone, Debug, PartialEq)]
        pub struct Func {
            /// All the existing signatures for this function. A function
            /// can have multiple signatures that differ in their arguments
            /// or return type.
            pub signatures: Vec<FuncSignature>,
        }

        impl From<Rc<types::Func>> for Func {
            fn from(func: Rc<types::Func>) -> Self {
                let mut signatures =
                    Vec::with_capacity(func.signatures().len());

                for signature in func.signatures() {
                    signatures.push(FuncSignature {
                        args: signature
                            .args
                            .iter()
                            .map(|(name, ty)| (name.clone(), Type::from(ty)))
                            .collect(),
                        ret: Type::from(&signature.result),
                        doc: signature.doc.clone(),
                    });
                }

                Func { signatures }
            }
        }

        /// Describes a function signature.
        #[derive(Clone, Debug, PartialEq)]
        pub struct FuncSignature {
            /// The names and types of the function arguments.
            args: Vec<(String, Type)>,
            /// The return type for the function.
            ret: Type,
            /// Function's documentation.
            doc: Option<Cow<'static, str>>,
        }

        impl FuncSignature {
            /// The names and types of the function arguments.
            pub fn args(
                &self,
            ) -> impl ExactSizeIterator<Item = (&str, &Type)> {
                self.args.iter().map(|(name, ty)| (name.as_str(), ty))
            }

            /// The return type for the function.
            pub fn ret_type(&self) -> &Type {
                &self.ret
            }

            /// Function's documentation.
            pub fn doc(&self) -> Option<&str> {
                self.doc.as_deref()
            }
        }

        /// Describes a field within a structure or module.
        #[derive(Clone)]
        pub struct Field<'a> {
            name: &'a str,
            struct_field: &'a types::StructField,
        }

        impl<'a> Field<'a> {
            fn new(
                name: &'a str,
                struct_field: &'a types::StructField,
            ) -> Self {
                Self { name, struct_field }
            }

            /// Returns the name of the field.
            pub fn name(&self) -> &'a str {
                self.name
            }

            /// Returns the type of the field.
            pub fn ty(&self) -> Type {
                Type::from(&self.struct_field.type_value)
            }

            /// Returns the documentation for the current field.
            pub fn doc(&self) -> Option<&str> {
                self.struct_field.doc
            }
        }

        /// The type of field, function argument or return value.
        #[derive(Clone, Debug, PartialEq)]
        pub enum Type {
            /// An integer.
            Integer,
            /// A float.
            Float,
            /// A boolean.
            Bool,
            /// A string.
            String,
            /// A regular expression
            Regexp,
            /// A structure.
            Struct(Struct),
            /// An array.
            Array(Box<Type>),
            /// A map.
            Map(Box<Type>, Box<Type>),
            /// A function.
            Func(Func),
        }

        impl From<&TypeValue> for Type {
            fn from(type_value: &TypeValue) -> Self {
                match type_value {
                    TypeValue::Bool { .. } => Type::Bool,
                    TypeValue::Float { .. } => Type::Float,
                    TypeValue::Integer { .. } => Type::Integer,
                    TypeValue::String { .. } => Type::String,
                    TypeValue::Regexp(_) => Type::Regexp,
                    TypeValue::Struct(s) => {
                        Type::Struct(Struct::new(s.clone()))
                    }
                    TypeValue::Array(a) => {
                        Type::Array(Box::new(Type::from(&a.deputy())))
                    }
                    TypeValue::Map(m) => {
                        let key_kind = match **m {
                            Map::IntegerKeys { .. } => Type::Integer,
                            Map::StringKeys { .. } => Type::String,
                        };
                        Type::Map(
                            Box::new(key_kind),
                            Box::new(Type::from(&m.deputy())),
                        )
                    }
                    TypeValue::Func(func) => Type::Func(func.clone().into()),
                    TypeValue::Unknown => unreachable!(),
                }
            }
        }
    }
}

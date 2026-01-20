use protobuf::descriptor::{
    DescriptorProto, EnumDescriptorProto, FileDescriptorProto,
};
use quote::ToTokens;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use syn::{Expr, File, FnArg, Item, Lit, Meta, Pat, ReturnType, Type};

use yara_x_proto::exts::enum_options as yara_enum_options;
use yara_x_proto::exts::field_options as yara_field_options;
use yara_x_proto::exts::message_options as yara_message_options;
use yara_x_proto::exts::module_options as yara_module_options;

/// Contains the name of the module and the AST of Rust code in which
/// definitions of the functions of this module (`#[module_export]`)
/// are located.
struct ModuleDefinition {
    pub module_name: String,
    pub ast: File,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum ModuleItemKind {
    Function,
    Property,
    Constant,
    Structure, // This represents module or its nested structure
}

impl ModuleItemKind {
    /// Converts `ModuleItemKind` to the corresponding LSP completion item kind from `lsp_types` crate.
    fn to_completion_item_kind(self) -> String {
        match self {
            ModuleItemKind::Function => {
                "CompletionItemKind::FUNCTION".to_string()
            }
            ModuleItemKind::Property => {
                "CompletionItemKind::PROPERTY".to_string()
            }
            ModuleItemKind::Constant => {
                "CompletionItemKind::CONSTANT".to_string()
            }
            ModuleItemKind::Structure => {
                "CompletionItemKind::MODULE".to_string()
            }
        }
    }
}

impl Default for ModuleItemKind {
    fn default() -> Self {
        Self::Structure
    }
}

/// Structure containing information about a specific symbol in the context of a specific module.
///
/// This can represent:
/// 1. the module itself (e.g. `pe` module)
/// 2. its structure (e.g. `rich_signature` in `pe` module)
/// 3. a function (e.g. `calculate_checksum()` in `pe` module)
/// 4. a field (e.g. `is_pe` in `pe` module)
/// 5. a constant (e.g. `MACHINE_UNKNOWN` in `pe` module)
#[derive(Debug, Default)]
struct ModuleItem {
    /// Signature of the module, nested structure, constant, function or field
    pub signature: String,
    /// Provided documentation from Rust source code or proto definition (in the future)
    pub documentation: Option<String>,
    /// Function arguments as (argument_name, argument_type)
    pub arguments: Vec<(String, String)>,
    /// Function return type
    pub return_type: Option<String>,
    /// Kind of this symbol in the context of a specific module
    pub kind: ModuleItemKind,
    /// Nested structures of this module
    pub structure: HashMap<String, ModuleItem>,
    /// Function, constants, fields of the module or nested structure
    pub items: Vec<ModuleItem>,
    /// If it is representing an indexed structure (e.g. `sections` in `pe` module)
    pub indexed: bool,
}

impl ModuleItem {
    /// Converts `ModuleItem` to Rust source code containing hashmap definition.
    /// Each module (and its nested structures) has its own hashmap definition,
    /// whose values are the symbols that exist in that module (or structure).
    pub fn to_hasmap_definition(&self, ancestors: Vec<String>) -> String {
        // Constructing hashmap name
        // For example, structure `pe.rich_signature` will have ["pe"] as ancestors
        // and the name of the hash map in the code will be `HASHMAP_pe_rich_signature`
        let mut hashmap = String::new();
        let ancestors_prefix = if ancestors.is_empty() {
            String::from("_")
        } else {
            format!("_{}_", ancestors.join("_"))
        };
        let hasmap_name = format!("{}{}", ancestors_prefix, self.signature);

        // OnceLock hashmap definition and getter
        hashmap.push_str(&format!(
            "static HASHMAP{hasmap_name}: OnceLock<HashMap<&'static str, Vec<ItemModule>>> = OnceLock::new();
fn __get_HASHMAP{hasmap_name}() -> &'static HashMap<&'static str, Vec<ItemModule>> {{
    HASHMAP{hasmap_name}.get_or_init(|| {{
        let mut hashmap = HashMap::new();\n",
        ));

        // Process nested structures
        let mut ancestors_and_self = ancestors.clone();
        ancestors_and_self.push(self.signature.clone());
        for item in self.structure.values() {
            // Generate Rust source code containing hashmap defintion of nested structure items
            // and insert it before current hashmap definition
            hashmap.insert_str(
                0,
                &item.to_hasmap_definition(ancestors_and_self.clone()),
            );
            // Generate Rust source code containing hashmap entry for nested structure
            hashmap.push_str(&format!(
                "\t\thashmap.insert(\"{}\", vec![{}]);\n",
                item.signature,
                item.to_hashmap_item_module(Some(ancestors_and_self.clone()))
            ));
        }

        // Collect all unique identifiers of items in the structure (or module)
        let distinct_names = &self
            .items
            .iter()
            .map(|item| item.signature.clone())
            .collect::<HashSet<String>>();

        // Process constants, functions and fields
        for name in distinct_names {
            // Hashmap entry for unique identifier
            hashmap.push_str(&format!("\t\thashmap.insert(\"{name}\", vec!["));

            // Get values for this hashmap entry.
            // Finding unique symbols was needed so that we could collect
            // all variations of functions with the same signature here.
            let nested_item_string = self
                .items
                .iter()
                .filter(|item| &item.signature == name)
                .map(|item| item.to_hashmap_item_module(None))
                .collect::<Vec<String>>()
                .join(", ");

            // Close hasmap entry
            hashmap.push_str(&nested_item_string);
            hashmap.push_str("]);\n");
        }

        // Close hashmap getter function
        hashmap.push_str(
            "\t\thashmap
        }
    )
}\n",
        );

        hashmap
    }

    /// Converts `ModuleItem` to Rust source code containing hashmap (key, value) pair.
    /// Each constant, field or function has its own (key, value) in hashmap of corresponding
    /// module or nested structure.
    ///
    /// The key of this pair is the symbol.
    /// The value of this pair is a vector of `ItemModule` structures, since there could be
    /// more than one function with the same name.
    fn to_hashmap_item_module(
        &self,
        ancestors: Option<Vec<String>>,
    ) -> String {
        let mut item_module_value = "ItemModule {".to_string();

        // Documentation
        item_module_value.push_str("doc: ");
        // General information about symbol
        match self.kind {
            ModuleItemKind::Constant | ModuleItemKind::Property => {
                item_module_value.push_str(&format!(
                    "Some(r#\" ### `{}` -> ",
                    self.signature
                ))
            }
            ModuleItemKind::Function => item_module_value.push_str(&format!(
                "Some(r#\" ### `{}({})` -> ",
                self.signature,
                self.arguments
                    .iter()
                    .map(|arg| arg.1.clone())
                    .collect::<Vec<String>>()
                    .join(", ")
            )),
            ModuleItemKind::Structure => item_module_value.push_str(&format!(
                "Some(r#\" ### `{}` structure ",
                self.signature
            )),
        }

        if self.kind != ModuleItemKind::Structure {
            if let Some(return_type) = &self.return_type {
                item_module_value.push_str(&format!("`{return_type}`"));
            } else {
                item_module_value.push_str("()");
            }
        }
        // Provided documentation about this symbol
        if let Some(docs) = &self.documentation {
            item_module_value.push_str(&format!("\n\n{docs}"));
        }
        item_module_value.push_str("\"#), ");

        // Structure of this symbol or its array values
        item_module_value.push_str("structure:");
        if self.kind == ModuleItemKind::Structure {
            if let Some(ancestors) = &ancestors {
                let ancestors_part = if ancestors.is_empty() {
                    String::from("_")
                } else {
                    format!("_{}_", ancestors.join("_"))
                };
                let typ = if self.indexed { "Indexed" } else { "Single" };
                item_module_value.push_str(&format!(
                    "Some(ItemStructure::{}(__get_HASHMAP{ancestors_part}{}())),",
                    typ,
                    self.signature
                ));
            }
        } else {
            item_module_value.push_str("None, ");
        }

        // Insert text for Code Completion feature
        item_module_value.push_str("insert_text: ");
        if self.kind == ModuleItemKind::Function {
            item_module_value.push_str(&format!(
                "Some(\"{}({})\"), ",
                self.signature,
                self.arguments
                    .iter()
                    .enumerate()
                    .map(|(i, arg)| format!("${{{}:{}}}", i + 1, arg.0))
                    .collect::<Vec<String>>()
                    .join(", ")
            ));
        } else {
            item_module_value.push_str("None,");
        }

        // Completiom item kind for Code Completion feature
        item_module_value.push_str(&format!(
            "kind: {},",
            self.kind.to_completion_item_kind()
        ));

        // Signature information for functions directly as `lsp_types::SignatureInformation`
        if self.kind == ModuleItemKind::Function {
            item_module_value
                .push_str("sign_info: Some(SignatureInformation {");
            let mut label = format!("{}(", self.signature);
            let mut parameter_locations: Vec<(usize, usize)> = vec![];
            let mut current_length = label.len();

            for (arg_name, arg_type) in &self.arguments {
                if !label.ends_with('(') {
                    label.push_str(", ");
                }
                let label_params = format!("{arg_name}: {arg_type}");
                parameter_locations.push((
                    current_length,
                    current_length + label_params.len(),
                ));
                current_length += label_params.len() + 2;
                label.push_str(&label_params);
            }
            label.push(')');
            item_module_value
                .push_str(&format!("label: String::from(r#\"{label}\"#), "));

            if let Some(docs) = &self.documentation {
                item_module_value.push_str(&format!(
                    "documentation: Some(Documentation::String(String::from(r#\"{docs}\"#))), ",
                ));
            } else {
                item_module_value.push_str("documentation: None, ");
            }

            if parameter_locations.is_empty() {
                item_module_value.push_str("parameters: None,");
            } else {
                item_module_value.push_str("parameters: Some(vec![");
                for (start, end) in parameter_locations {
                    if !item_module_value.ends_with('[') {
                        item_module_value.push_str(", ");
                    }
                    item_module_value.push_str(&format!("ParameterInformation {{ label: ParameterLabel::LabelOffsets([{start}, {end}]), documentation: None }}"));
                }
                item_module_value.push_str("]),");
            }

            item_module_value.push_str("active_parameter: None");
            item_module_value.push_str("})");
        } else {
            item_module_value.push_str("sign_info: None");
        }

        item_module_value.push('}');

        item_module_value
    }
}

/// Structure containing each module as (module name, `ModuleItem` of module) pair.
struct YaraModules(HashMap<String, ModuleItem>);

impl YaraModules {
    pub fn new() -> Self {
        YaraModules(HashMap::new())
    }

    /// Finds (or creates) nested structure based on provided path.
    fn find_structure(&mut self, mut path: Vec<String>) -> &mut ModuleItem {
        path.reverse();

        // Module name
        let first_signature = path.pop().unwrap();

        // Find (or create) the module or nested structure
        let mut module_item =
            self.0.entry(first_signature.clone()).or_insert(ModuleItem {
                signature: first_signature,
                ..Default::default()
            });

        while let Some(next_signature) = path.pop() {
            module_item = module_item
                .structure
                .entry(next_signature.clone())
                .or_insert(ModuleItem {
                    signature: next_signature,
                    ..Default::default()
                });
        }

        module_item
    }

    /// Adds constant, function or field to the corresponding nested structure
    /// or module based on path in `signature`.
    pub fn add_item(
        &mut self,
        kind: ModuleItemKind,
        signature: &str,
        arguments: Vec<(String, String)>,
        documentation: Option<String>,
        return_type: Option<String>,
    ) {
        let mut signatures = signature
            .split(".")
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        let last_signature = signatures.pop().unwrap();

        let structure = self.find_structure(signatures);

        structure.items.push(ModuleItem {
            signature: last_signature,
            documentation,
            arguments,
            return_type,
            kind,
            ..Default::default()
        });
    }

    /// Generates root hashmap containing entry for each module and module hashmaps
    pub fn generate_hasmaps(&self) -> String {
        let mut hashmaps = String::new();
        let mut modules_hashmap = String::from(
            "static MODULES: OnceLock<HashMap<&'static str, Vec<ItemModule>>> = OnceLock::new();
fn __get_modules() -> &'static HashMap<&'static str, Vec<ItemModule>> {
    MODULES.get_or_init(|| {
    let mut hashmap = HashMap::new();",
        );

        for (name, item) in &self.0 {
            hashmaps.push_str(&item.to_hasmap_definition(Vec::new()));
            modules_hashmap.push_str(&format!(
                "\t\thashmap.insert(\"{name}\", vec![ItemModule {{doc: None, structure: Some(ItemStructure::Single(__get_HASHMAP_{name}())), insert_text: None, kind: {}, sign_info: None}}]);\n",
                item.kind.to_completion_item_kind()
            ));
        }
        modules_hashmap.push_str(
            "\t\thashmap
            })
        }\n",
        );
        hashmaps.insert_str(0, &modules_hashmap);

        hashmaps
    }
}

// Founds message in provided input protos and imports by message name
fn find_message_by_full_name<'a>(
    protos: &'a [FileDescriptorProto],
    imports: &'a [FileDescriptorProto],
    full_message_name: &str,
) -> Option<&'a DescriptorProto> {
    // First, try to found the message in input protos
    if let Some(dp) = protos.iter().find_map(|fdp| {
        //Check if full name contains the same package
        if full_message_name.contains(fdp.package()) {
            fdp.message_type.iter().find(|&message| {
                //Check that the last part of the full name is the same as the message name
                if let Some(root_message_name) =
                    full_message_name.split(".").last()
                {
                    return message.name() == root_message_name;
                }
                false
            })
        } else {
            None
        }
    }) {
        Some(dp)
    }
    // If failed, then try to found the message in imports
    else if let Some(dp) = imports.iter().find_map(|fdp| {
        if full_message_name.contains(fdp.package()) {
            fdp.message_type.iter().find(|&message| {
                if let Some(root_message_name) =
                    full_message_name.split(".").last()
                {
                    return message.name() == root_message_name;
                }
                false
            })
        } else {
            None
        }
    }) {
        Some(dp)
    } else {
        None
    }
}

// Processes all input protos for a specific module
fn process_proto_module_definition(
    yara_modules: &mut YaraModules,
    protos: &[FileDescriptorProto],
    imports: &[FileDescriptorProto],
    module_name: &str,
) {
    // Start from root message
    let module_options = protos.iter().find_map(|fdp| {
        if let Some(module_options) = yara_module_options.get(&fdp.options) {
            if module_options.name() == module_name {
                Some(module_options.clone())
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(module_options) = module_options {
        if let Some(root_message) = find_message_by_full_name(
            protos,
            imports,
            module_options.root_message(),
        ) {
            process_message_proto(
                yara_modules,
                protos,
                imports,
                root_message,
                module_name,
            );

            // Collects all constants of this module from all proto enumerations
            for edp in protos.iter().flat_map(|p| &p.enum_type) {
                process_enum_proto(yara_modules, edp, module_name);
            }
        }
    }
}

/// Processes proto enumeration to extract constants of a specific module
fn process_enum_proto(
    yara_modules: &mut YaraModules,
    edp: &EnumDescriptorProto,
    module_name: &str,
) {
    let mut signature = String::from(module_name);

    if let Some(options) = yara_enum_options.get(&edp.options) {
        if options.has_name() {
            signature.push('.');
            signature.push_str(options.name());
        } else if !options.inline() {
            signature.push('.');
            signature.push_str(edp.name());
        }
    }

    for value in &edp.value {
        yara_modules.add_item(
            ModuleItemKind::Constant,
            &format!("{}.{}", signature, value.name()),
            vec![],
            None,
            Some("integer".to_string()),
        );
    }
}

fn process_message_proto(
    yara_modules: &mut YaraModules,
    protos: &[FileDescriptorProto],
    imports: &[FileDescriptorProto],
    message: &DescriptorProto,
    module_name: &str,
) {
    let mut nested_structures_name = format!(
        "{}.{}",
        module_name.split(".").next().unwrap(),
        message.name()
    );

    if let Some(options) = yara_message_options.get(&message.options) {
        if options.has_name() {
            nested_structures_name = format!(
                "{}.{}",
                module_name.split(".").next().unwrap(),
                options.name()
            )
        }
    }

    //Process nested enumerations within message
    message.enum_type.iter().for_each(|nested_enum| {
        process_enum_proto(
            yara_modules,
            nested_enum,
            nested_structures_name.as_str(),
        )
    });

    for field in &message.field {
        let mut signature = field.name().to_string();

        if let Some(field_options) = yara_field_options.get(&field.options) {
            if field_options.ignore() {
                continue;
            }
            if field_options.has_name() {
                signature = field_options.name.unwrap();
            }
        }

        let return_type = field.type_();
        let label = match field.label() {
            protobuf::descriptor::field_descriptor_proto::Label::LABEL_REPEATED => "[]",
            _ => "",
        };

        // Primitive types
        if let Some(interpreted) = interpret_type_proto(return_type) {
            yara_modules.add_item(
                ModuleItemKind::Property,
                &format!("{module_name}.{signature}"),
                vec![],
                None,
                Some(format!("{interpreted}{label}")),
            );
        }
        // Constants
        else if let protobuf::descriptor::field_descriptor_proto::Type::TYPE_ENUM = return_type {
            // Full path to this enumeration is starting which is removed
            let type_name = &field.type_name()[1..];
            yara_modules.add_item(
                ModuleItemKind::Property,
                &format!("{module_name}.{signature}"),
                vec![],
                None,
                Some(format!("{type_name}{label}")),
            );
        }
        // Message, which could be a nested structure or a map
        else if protobuf::descriptor::field_descriptor_proto::Type::TYPE_MESSAGE == return_type {
            let item_name = format!("{module_name}.{signature}");

            // Processing protobuf `map` type
            if field.type_name().ends_with("Entry") {
                let map_message = if let Some(res) = message
                    .nested_type
                    .iter()
                    .find(|dp| dp.name() == field.type_name().split(".").last().unwrap())
                {
                    res
                } else {
                    continue;
                };

                let key_type =  if let Some(interpreted) = map_message.field
                    .iter()
                    .find(|fdp| fdp.name() == "key")
                    .and_then(|key_field| interpret_type_proto(key_field.type_()))
                {
                    interpreted
                } else {
                    continue;
                };

                let value_type = if let Some(interpreted) = map_message.field
                    .iter()
                    .find(|fdp| fdp.name() == "value")
                    .and_then(|value_field| interpret_type_proto(value_field.type_()))
                {
                    interpreted
                } else {
                    continue;
                };

                yara_modules.add_item(
                    ModuleItemKind::Property,
                    &item_name,
                    vec![],
                    None,
                    Some(format!("map<{key_type}, {value_type}>")),
                );
            }
            // Recursively process message from the same proto input if there is
            else if let Some(message) = message
                .nested_type
                .iter()
                .find(|nested| field.type_name().contains(nested.name()))
            {
                process_message_proto(yara_modules, protos, imports, message, &item_name);
            }
            // Otherwise try to find message in imports or other provided input protos
            // for a specific module and process it recursively
            else if let Some(message) =
                find_message_by_full_name(protos, imports, field.type_name())
            {
                process_message_proto(yara_modules, protos, imports, message, &item_name);
            }

            // Don't mark field as indexed if it is a map
            if !field.type_name().ends_with("Entry") && label == "[]"{
                yara_modules
                    .find_structure(
                        item_name
                            .split(".")
                            .map(|s| s.to_string())
                            .collect::<Vec<String>>(),
                    )
                    .indexed = true;
            }
        }
    }
}

// Fill protobuf parser with inputs from `src/modules/protos/`
fn get_proto_inputs(
    proto_directory: PathBuf,
    parser: &mut protobuf_parse::Parser,
) {
    let mut directories: Vec<PathBuf> = vec![proto_directory];

    while let Some(dir) = directories.pop() {
        for proto_item in dir.read_dir().unwrap().flatten() {
            if proto_item.file_type().unwrap().is_file() {
                parser.input(proto_item.path());
            } else if proto_item.file_type().unwrap().is_dir() {
                directories.push(proto_item.path());
            }
        }
    }
}

/// This function finds all modules and paths to Rust code in `src/modules` directory
fn get_module_definitions(module_directory: PathBuf) -> Vec<ModuleDefinition> {
    let mut result: Vec<ModuleDefinition> = Vec::new();
    let mut directories: Vec<PathBuf> = vec![module_directory];

    while let Some(dir) = directories.pop() {
        for item in dir.read_dir().unwrap().flatten() {
            // Try to search in other directories
            if item.file_type().unwrap().is_dir()
                && !item
                    .file_name()
                    .into_string()
                    .unwrap()
                    .contains("test_proto")
            {
                directories.push(item.path());
            }
            // Find Rust file with module definition
            else if item.path().extension().is_some_and(|ext| ext == "rs") {
                let code = &fs::read_to_string(item.path())
                    .expect("Failed to read module source code");
                let ast: File;
                if let Ok(parsed) = syn::parse_file(code.as_str()) {
                    ast = parsed;
                } else {
                    continue;
                }

                //If there is #[module_main] attribute, consider this file as module definition
                let module_main_existence = ast.items.iter().any(|item| {
                    if let Item::Fn(fun) = item {
                        return fun.attrs.iter().any(|attribute| {
                            if let Some(first_segment) =
                                attribute.meta.path().segments.first()
                            {
                                first_segment.ident == "module_main"
                            } else {
                                false
                            }
                        });
                    }
                    false
                });
                if module_main_existence {
                    let file_name = item.file_name().into_string().unwrap();
                    if file_name == "mod.rs" {
                        if let Some(parent) = item.path().parent() {
                            if let Some(module_dir_name) = parent.file_name() {
                                result.push(ModuleDefinition {
                                    module_name: module_dir_name
                                        .to_str()
                                        .unwrap()
                                        .to_string(),
                                    ast,
                                });
                            }
                        }
                    } else {
                        result.push(ModuleDefinition {
                            module_name: file_name.replace(".rs", ""),
                            ast,
                        });
                    }
                }
            }
        }
    }

    result
}

/// Finds all functions of the module (Rust functions with #[module_export] attribute)
fn get_module_functions(
    yara_modules: &mut YaraModules,
    module_definition: &ModuleDefinition,
) {
    let module_functions =
        module_definition.ast.items.iter().filter_map(|item| {
            if let Item::Fn(fun) = item {
                Some(fun)
            } else {
                None
            }
        });

    for function in module_functions {
        let mut signature = String::new();
        let mut documentation: Option<String> = None;
        let mut arguments: Vec<(String, String)> = Vec::new();
        let mut return_type: Option<String> = None;

        for meta in function.attrs.iter().map(|attribute| &attribute.meta) {
            if let Some(first_segment) = meta.path().segments.first() {
                match first_segment.ident.to_string().as_str() {
                    // Extract documentation
                    "doc" => {
                        if let Meta::NameValue(metaname) = meta {
                            if let Expr::Lit(lit) = &metaname.value {
                                if let Lit::Str(lit) = &lit.lit {
                                    documentation = Some(lit.value());
                                }
                            }
                        }
                    }
                    // Extract function for `#[module_export]` attribute
                    // `method_of` parameter is not implemented yet
                    "module_export" => {
                        // Take a name parameter if there is
                        if let Meta::List(metalist) = meta {
                            if let Ok(Meta::NameValue(mnv)) =
                                metalist.parse_args::<syn::Meta>()
                            {
                                if mnv.path.is_ident("name") {
                                    if let Expr::Lit(lit) = &mnv.value {
                                        if let Lit::Str(str_lit) = &lit.lit {
                                            let extracted_name =
                                                str_lit.value();
                                            signature = format!(
                                                "{}.{extracted_name}",
                                                module_definition.module_name
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        // Otherwise take Rust function name
                        else {
                            signature = format!(
                                "{}.{}",
                                module_definition.module_name,
                                function.sig.ident
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        // There was no #[module_export] attribute
        if signature.is_empty() {
            continue;
        }

        //Function arguments
        function.sig.inputs.iter().skip(1).for_each(|arg| {
            if let FnArg::Typed(arg) = arg {
                if let Pat::Ident(ident) = arg.pat.as_ref() {
                    arguments.push((
                        ident.ident.to_string(),
                        if let Type::Path(arg_type) = arg.ty.as_ref() {
                            interpret_type(
                                arg_type.to_token_stream().to_string(),
                            )
                        } else {
                            "?".to_string()
                        },
                    ));
                }
            }
        });

        //Function return type
        if let ReturnType::Type(_, ty) = function.sig.output.clone() {
            if let Type::Path(ret_type) = ty.as_ref() {
                let full_type = ret_type.to_token_stream().to_string();
                return_type = Some(interpret_type(full_type));
            }
        }

        yara_modules.add_item(
            ModuleItemKind::Function,
            &signature,
            arguments,
            documentation,
            return_type,
        );
    }
}

/// Convert type of protobuf field to YARA-X type
fn interpret_type_proto(
    raw: protobuf::descriptor::field_descriptor_proto::Type,
) -> Option<String> {
    match raw {
        protobuf::descriptor::field_descriptor_proto::Type::TYPE_BOOL => {
            Some(String::from("bool"))
        }
        protobuf::descriptor::field_descriptor_proto::Type::TYPE_DOUBLE
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_FLOAT => {
            Some(String::from("float"))
        }
        protobuf::descriptor::field_descriptor_proto::Type::TYPE_STRING
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_BYTES => {
            Some(String::from("string"))
        }
        protobuf::descriptor::field_descriptor_proto::Type::TYPE_UINT32
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_UINT64
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_INT32
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_INT64
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_SINT32
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_SINT64
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_SFIXED32
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_SFIXED64
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_FIXED32
        | protobuf::descriptor::field_descriptor_proto::Type::TYPE_FIXED64 => {
            Some(String::from("integer"))
        }
        _ => None,
    }
}

/// Convert type from Rust source code to YARA-X type
fn interpret_type(raw: String) -> String {
    if raw.contains("RuntimeString")
        || raw.contains("FixedLenString")
        || raw.contains("RegexpId")
    {
        "string".to_string()
    } else if raw.contains("i64") {
        "integer".to_string()
    } else if raw.contains("f64") {
        "float".to_string()
    } else if raw.contains("bool") {
        "bool".to_string()
    } else {
        raw
    }
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let mut out_file =
        std::fs::File::create(Path::new(&out_dir).join("module_tables.rs"))
            .unwrap();

    let modules_dir = PathBuf::from("../lib/src/modules/");

    //Obtain all modules with corresponding Rust implementation
    let module_definitions = get_module_definitions(modules_dir.clone());

    //Parses all proto files
    let mut parser = protobuf_parse::Parser::new();
    parser.pure().include(modules_dir.join("protos"));

    get_proto_inputs(modules_dir.join("protos/"), &mut parser);

    let parsed = parser.parse_and_typecheck().unwrap();

    let mut yara_modules = YaraModules::new();

    for module_def in &module_definitions {
        get_module_functions(&mut yara_modules, module_def);

        let protos_module = parsed
            .file_descriptors
            .iter()
            .filter(|fdp| fdp.package().starts_with(&module_def.module_name))
            .cloned()
            .collect::<Vec<FileDescriptorProto>>();

        if !protos_module.is_empty() {
            let imports = protos_module
                .iter()
                .flat_map(|proto| &proto.dependency)
                .cloned()
                .collect::<Vec<String>>();

            let imports = parsed
                .file_descriptors
                .iter()
                .filter(|fdp| {
                    imports.contains(&fdp.name().to_string())
                        && fdp.name() != "yara.proto"
                })
                .cloned()
                .collect::<Vec<FileDescriptorProto>>();

            process_proto_module_definition(
                &mut yara_modules,
                &protos_module,
                &imports,
                &module_def.module_name,
            );
        }
    }

    //Module hashmaps
    write!(out_file, "{}", yara_modules.generate_hasmaps()).unwrap();

    println!("cargo::rerun-if-changed=build.rs");
}

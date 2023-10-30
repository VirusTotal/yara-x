use protobuf::reflect::MessageRef;
use protobuf::reflect::ReflectFieldRef;
use protobuf::reflect::ReflectValueRef;
use yara_x_proto::exts::field_options;

use crate::Error;

// A struct that represents serializers
struct JsonSerializer;
struct YamlSerializer;
struct TomlSerializer;
struct XmlSerializer;

// A trait for any type that can serialize a message
pub(crate) trait Serializer {
    fn serialize(&self, message: String) -> Result<String, Error>;
}

// Implement the trait for the JSON serializer
impl Serializer for JsonSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_json::Value>(&message)?;
        Ok(serde_json::to_string_pretty(&value)?)
    }
}

// Implement the trait for the YAML serializer
impl Serializer for YamlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<serde_yaml::Value>(&message)?;
        Ok(serde_yaml::to_string(&value)?)
    }
}

// Implement the trait for the TOML serializer
impl Serializer for TomlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let value = serde_json::from_str::<toml::Value>(&message)?;
        Ok(toml::to_string_pretty(&value)?)
    }
}

// Implement the trait for the XML serializer
impl Serializer for XmlSerializer {
    fn serialize(&self, message: String) -> Result<String, Error> {
        let mut xml_builder = xml2json_rs::XmlConfig::new()
            .rendering(xml2json_rs::Indentation::new(b' ', 2))
            .decl(xml2json_rs::Declaration::new(
                xml2json_rs::Version::XML10,
                Some(xml2json_rs::Encoding::UTF8),
                Some(true),
            ))
            .root_name("file")
            .finalize();
        let xml = xml_builder.build_from_json_string(&message)?;
        Ok(xml)
    }
}

// A function that returns a trait object based on the format
pub fn get_serializer(format: &str) -> Result<Box<dyn Serializer>, Error> {
    match format {
        // Return a JSON serializer
        "json" => Ok(Box::new(JsonSerializer)),
        // Return a YAML serializer
        "yaml" => Ok(Box::new(YamlSerializer)),
        // Return a TOML serializer
        "toml" => Ok(Box::new(TomlSerializer)),
        // Return an XML serializer
        "xml" => Ok(Box::new(XmlSerializer)),
        // Return an error if the format is unsupported
        _ => Err(Error::UnsupportedFormat),
    }
}

pub fn get_human_readable_output(msg: &MessageRef) -> String {
    let desc = msg.descriptor_dyn();

    for f in desc.fields() {
        match f.get_reflect(&**msg) {
            ReflectFieldRef::Map(map) => {
                println!("{:?}", map)
            }
            ReflectFieldRef::Repeated(repeated) => {
                println!("{:?}", repeated)
            }
            ReflectFieldRef::Optional(optional) => {
                if let Some(options) = field_options.get(&f.proto().options) {
                    if options.hex_value.unwrap_or(false) {
                        match optional.value().unwrap() {
                            ReflectValueRef::Message(m) => {}
                            ReflectValueRef::Enum(d, v) => {}
                            ReflectValueRef::String(s) => {}
                            ReflectValueRef::Bytes(b) => {}
                            ReflectValueRef::I32(v) => {}
                            ReflectValueRef::I64(v) => {}
                            ReflectValueRef::U32(v) => {
                                println!("{:x}", v)
                            }
                            ReflectValueRef::U64(v) => {}
                            ReflectValueRef::Bool(v) => {}
                            ReflectValueRef::F32(v) => {}
                            ReflectValueRef::F64(v) => {}
                        }
                    }
                }
                println!("{:?}", optional.value())
            }
        }
        if let Some(options) = field_options.get(&f.proto().options) {
            println!("{:?}", options)
        }
    }

    return "Test".to_string();
}

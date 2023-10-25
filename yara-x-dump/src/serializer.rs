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

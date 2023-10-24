use crate::Error;

// A struct that represents serializers
struct JsonSerializer;
struct YamlSerializer;

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

// A function that returns a trait object based on the format
pub fn get_serializer(format: &str) -> Result<Box<dyn Serializer>, Error> {
    match format {
        // Return a JSON serializer
        "json" => Ok(Box::new(JsonSerializer)),
        // Return a YAML serializer
        "yaml" => Ok(Box::new(YamlSerializer)),
        // Return an error if the format is unsupported
        _ => Err(Error::UnsupportedFormat),
    }
}

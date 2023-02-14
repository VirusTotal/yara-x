use crate::types::TypeValue;
use bstr::BString;
use indexmap::IndexMap;

pub enum Map {
    /// A map that has integer keys.
    IntegerKeys {
        // The deputy value is one that acts as a representative of the values
        // stored in the map. This value only contains type information, not
        // actual data. For example, if the value is an integer it will be
        // Value::Integer(None), if it is a structure, it will have the
        // same fields than actual structures stored in the map, but those
        // fields will contain no data. The deputy value is optional because
        // it is present only at compile time, when the `map` field is an
        // empty map.
        deputy: Option<TypeValue>,
        // Use IndexMap instead of HashMap because IndexMap allows to get an
        // item not only by key, but also by index. HashMap doesn't offer
        // that functionality (it doesn't even have a stable iterator that
        // returns the items in a predictable order).
        map: IndexMap<i64, TypeValue>,
    },
    /// A map that has string keys.
    StringKeys { deputy: Option<TypeValue>, map: IndexMap<BString, TypeValue> },
}

impl Map {
    pub fn deputy(&self) -> TypeValue {
        match self {
            Map::IntegerKeys { deputy, .. } => {
                deputy.as_ref().unwrap().clone()
            }
            Map::StringKeys { deputy, .. } => deputy.as_ref().unwrap().clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        match self {
            Map::IntegerKeys { map, .. } => map.len(),
            Map::StringKeys { map, .. } => map.len(),
        }
    }
}

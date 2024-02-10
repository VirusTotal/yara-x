use bstr::BString;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::types::TypeValue;

#[derive(Serialize, Deserialize)]
pub(crate) enum Map {
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

    /// Returns the map as an [`IndexMap`] with integer keys.
    ///
    /// # Panics
    ///
    /// If the map is not the [`Map::IntegerKeys`] variant.
    pub fn with_integer_keys(&self) -> &IndexMap<i64, TypeValue> {
        match self {
            Map::IntegerKeys { map, .. } => map,
            _ => panic!("calling `with_integers_keys` on an map that is not `Map::IntegerKeys`"),
        }
    }

    /// Returns the map as an [`IndexMap`] with integer keys.
    ///
    /// # Panics
    ///
    /// If the map is not the [`Map::StringKeys`] variant.
    pub fn with_string_keys(&self) -> &IndexMap<BString, TypeValue> {
        match self {
            Map::StringKeys { map, .. } => map,
            _ => panic!("calling `with_string_keys` on an map that is not `Map::StringKeys`"),
        }
    }

    /// Returns the number of items in the map.
    pub fn len(&self) -> usize {
        match self {
            Map::IntegerKeys { map, .. } => map.len(),
            Map::StringKeys { map, .. } => map.len(),
        }
    }
}

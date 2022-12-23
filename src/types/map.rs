use crate::types::TypeValue;
use bstr::BString;
use rustc_hash::FxHashMap;

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
        map: FxHashMap<i64, TypeValue>,
    },
    /// A map that has string keys.
    StringKeys {
        deputy: Option<TypeValue>,
        map: FxHashMap<BString, TypeValue>,
    },
}

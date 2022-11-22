use bstr::BStr;
use bstr::ByteSlice;
use intaglio::Symbol;

#[derive(Clone, Copy)]
pub struct StringId(u32);

impl StringId {
    #[inline]
    pub fn id(&self) -> u32 {
        self.0
    }
}

/// StringPool is a data structure for interning strings.
///
/// For each interned string it returns a [`StringID`] that can be used
/// retrieving the string again. A single copy of each string is stored
/// in a [`StringPool`].
pub struct StringPool {
    pool: intaglio::SymbolTable,
}

impl StringPool {
    /// Creates a new [`StringPool`].
    pub fn new() -> Self {
        Self { pool: intaglio::SymbolTable::new() }
    }

    /// Returns the [`StringID`] corresponding to `s`. Interns the string
    /// if not already interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &str) -> StringId {
        StringId(self.pool.intern(s.to_string()).unwrap().id())
    }

    /// Returns the string corresponding to [`StringID`] if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, s: StringId) -> Option<&str> {
        self.pool.get(Symbol::from(s.0))
    }
}

pub struct BStringPool {
    pool: intaglio::bytes::SymbolTable,
}

impl BStringPool {
    /// Creates a new [`BStringPool`].
    pub fn new() -> Self {
        Self { pool: intaglio::bytes::SymbolTable::new() }
    }

    /// Returns the [`StringID`] corresponding to `s`. Interns the string
    /// if not already interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &BStr) -> StringId {
        let bytes = s.as_bytes();
        StringId(self.pool.intern(bytes.to_vec()).unwrap().id())
    }

    /// Returns the string corresponding to [`StringID`] if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, s: StringId) -> Option<&BStr> {
        self.pool.get(Symbol::from(s.0)).map(BStr::new)
    }
}

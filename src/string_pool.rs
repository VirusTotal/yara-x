use intaglio::Symbol;

/// StringPool is a data structure for interning strings.
///
/// For each interned string it returns a [`StringID`] that can be used
/// retrieving the string again. A single copy of each string is stored
/// in a [`StringPool`].
pub struct StringPool {
    pool: intaglio::SymbolTable,
}

#[derive(Clone, Copy)]
pub struct StringID(u32);

impl StringID {
    #[inline]
    pub fn id(&self) -> u32 {
        self.0
    }
}

impl StringPool {
    /// Creates a new [`StringPool`].
    pub fn new() -> Self {
        Self { pool: intaglio::SymbolTable::new() }
    }

    /// Returns the [`StringID`] corresponding to `s`. Interns the string
    /// if not already interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &str) -> StringID {
        StringID(self.pool.intern(s.to_string()).unwrap().id())
    }

    /// Returns the string corresponding to [`StringID`] if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, s: StringID) -> Option<&str> {
        self.pool.get(Symbol::from(s.0))
    }
}

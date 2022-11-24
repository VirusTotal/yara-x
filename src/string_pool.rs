use bstr::BStr;
use bstr::ByteSlice;
use intaglio::Symbol;
use std::marker::PhantomData;

/// StringPool is a data structure for interning strings.
///
/// For each interned string it returns an ID of type `T`, that can be used
/// retrieving the string again. A single copy of each string is stored
/// in a [`StringPool`].
///
/// The type `T` must be convertible from and into `u32`.
pub struct StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    pool: intaglio::SymbolTable,
    phantom: PhantomData<T>,
}

impl<T> StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    /// Creates a new [`StringPool`].
    pub fn new() -> Self {
        Self {
            pool: intaglio::SymbolTable::new(),
            phantom: Default::default(),
        }
    }

    /// Returns the ID corresponding to `s`. Interns the string if not already
    /// interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &str) -> T {
        T::from(self.pool.intern(s.to_string()).unwrap().id())
    }

    /// Returns the string corresponding to a given ID if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, id: T) -> Option<&str> {
        self.pool.get(Symbol::from(id.into()))
    }
}

pub struct BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    pool: intaglio::bytes::SymbolTable,
    phantom: PhantomData<T>,
}

impl<T> BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    /// Creates a new [`BStringPool`].
    pub fn new() -> Self {
        Self {
            pool: intaglio::bytes::SymbolTable::new(),
            phantom: Default::default(),
        }
    }

    /// Returns the ID corresponding to `s`. Interns the string if not already
    /// interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &BStr) -> T {
        let bytes = s.as_bytes();
        T::from(self.pool.intern(bytes.to_vec()).unwrap().id())
    }

    /// Returns the string corresponding to a given ID if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, id: T) -> Option<&BStr> {
        self.pool.get(Symbol::from(id.into())).map(BStr::new)
    }
}

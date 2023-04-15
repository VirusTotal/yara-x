use bstr::BStr;
use intaglio::Symbol;
use rustc_hash::FxHasher;
use std::hash::BuildHasherDefault;
use std::marker::PhantomData;

/// Hash builder that replaces the default hashing algorithm used by string
/// pools (the same one used by [`std::collections::HashMap`]) with a faster
/// one [`rustc_hash::FxHasher`].
///
/// For more information see:
/// https://nnethercote.github.io/perf-book/hashing.html
type HashBuilder = BuildHasherDefault<FxHasher>;

/// StringPool is a data structure for interning strings.
///
/// For each interned string the pool returns an ID of type `T`, that can be
/// used for retrieving the string again. A single copy of each string is
/// stored in the pool.
///
/// The type `T` must be convertible from and into `u32`.
pub struct StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    pool: intaglio::SymbolTable<HashBuilder>,
    phantom: PhantomData<T>,
}

impl<T> StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    /// Creates a new [`StringPool`].
    pub fn new() -> Self {
        Self {
            pool: intaglio::SymbolTable::with_hasher(HashBuilder::default()),
            phantom: Default::default(),
        }
    }

    /// Returns the ID corresponding to the string `s`. Interns the string
    /// if not already interned.
    #[inline]
    pub fn get_or_intern(&mut self, s: &str) -> T {
        if let Some(s) = self.pool.check_interned(s) {
            T::from(s.id())
        } else {
            T::from(self.pool.intern(s.to_string()).unwrap().id())
        }
    }

    /// Returns the string corresponding to a given `id` if it was previously
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
    pool: intaglio::bytes::SymbolTable<HashBuilder>,
    phantom: PhantomData<T>,
}

impl<T> BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    /// Creates a new [`BStringPool`].
    pub fn new() -> Self {
        Self {
            pool: intaglio::bytes::SymbolTable::with_hasher(
                HashBuilder::default(),
            ),
            phantom: Default::default(),
        }
    }

    /// Returns the ID corresponding to `s`. Interns the string if not already
    /// interned.
    #[inline]
    pub fn get_or_intern<S>(&mut self, s: S) -> T
    where
        S: AsRef<[u8]>,
    {
        let bytes = s.as_ref();
        if let Some(s) = self.pool.check_interned(bytes) {
            T::from(s.id())
        } else {
            T::from(self.pool.intern(bytes.to_owned()).unwrap().id())
        }
    }

    /// Returns the string corresponding to a given ID if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, id: T) -> Option<&BStr> {
        self.pool.get(Symbol::from(id.into())).map(BStr::new)
    }

    /// Similar to [`BStringPool::get`], but returns the string as `&str`.
    ///
    /// # Panics
    ///
    /// If the interned string is not valid UTF-8.
    #[inline]
    pub fn get_str(&self, id: T) -> Option<&str> {
        self.pool
            .get(Symbol::from(id.into()))
            .map(|s| {
                std::str::from_utf8(s)
                    .expect("using BStringPool::get_str with a string that is not valid UTF-8")
            })
    }
}

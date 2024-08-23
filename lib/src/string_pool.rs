use bstr::BStr;
use intaglio::Symbol;
use rustc_hash::FxHasher;
use serde::de::Visitor;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
pub(crate) struct StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    pool: intaglio::SymbolTable<HashBuilder>,
    size: usize,
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
            size: 0,
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
            self.size += s.len();
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

impl<T> Serialize for StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.pool.len()))?;

        for string in self.pool.strings() {
            seq.serialize_element(string)?
        }

        seq.end()
    }
}

impl<'de, T> Deserialize<'de> for StringPool<T>
where
    T: From<u32> + Into<u32>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(StringPoolVisitor::new())
    }
}

struct StringPoolVisitor<T> {
    phantom: PhantomData<T>,
}

impl<T> StringPoolVisitor<T> {
    fn new() -> Self {
        Self { phantom: PhantomData }
    }
}

impl<'de, T> Visitor<'de> for StringPoolVisitor<T>
where
    T: From<u32> + Into<u32>,
{
    type Value = StringPool<T>;

    fn expecting(
        &self,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        formatter.write_str("a StringPool")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut pool = StringPool::new();

        while let Some(string) = seq.next_element()? {
            pool.get_or_intern(string);
        }

        Ok(pool)
    }
}

pub struct BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    pool: intaglio::bytes::SymbolTable<HashBuilder>,
    size: usize,
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
            size: 0,
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
            self.size += bytes.len();
            T::from(self.pool.intern(bytes.to_owned()).unwrap().id())
        }
    }

    /// Returns the string corresponding to a given ID if it was previously
    /// interned. If not returns [`None`].
    #[inline]
    pub fn get(&self, id: T) -> Option<&BStr> {
        self.get_bytes(id).map(BStr::new)
    }

    /// Similar to [`BStringPool::get`], but returns the string as `&[u8]`.
    #[inline]
    pub fn get_bytes(&self, id: T) -> Option<&[u8]> {
        self.pool.get(Symbol::from(id.into()))
    }

    /// Similar to [`BStringPool::get`], but returns the string as `&str`.
    ///
    /// # Panics
    ///
    /// If the interned string is not valid UTF-8.
    #[inline]
    pub fn get_str(&self, id: T) -> Option<&str> {
        self.get_bytes(id)
            .map(|s| {
                std::str::from_utf8(s)
                    .expect("using BStringPool::get_str with a string that is not valid UTF-8")
            })
    }
}

impl<T> Serialize for BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.pool.len()))?;

        for string in self.pool.bytestrings() {
            seq.serialize_element(string)?
        }

        seq.end()
    }
}

impl<'de, T> Deserialize<'de> for BStringPool<T>
where
    T: From<u32> + Into<u32>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BStringPoolVisitor::new())
    }
}

struct BStringPoolVisitor<T> {
    phantom: PhantomData<T>,
}

impl<T> BStringPoolVisitor<T> {
    fn new() -> Self {
        Self { phantom: PhantomData }
    }
}

impl<'de, T> Visitor<'de> for BStringPoolVisitor<T>
where
    T: From<u32> + Into<u32>,
{
    type Value = BStringPool<T>;

    fn expecting(
        &self,
        formatter: &mut std::fmt::Formatter,
    ) -> std::fmt::Result {
        formatter.write_str("a BStringPool")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut pool = BStringPool::new();

        while let Some(string) = seq.next_element::<&[u8]>()? {
            pool.get_or_intern(string);
        }

        Ok(pool)
    }
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use super::BStringPool;
    use super::StringPool;
    use bstr::BStr;

    #[test]
    fn string_pool_serde() {
        let mut pool: StringPool<u32> = StringPool::new();

        pool.get_or_intern("foo");
        pool.get_or_intern("bar");

        let serialized = bincode::serialize(&pool).unwrap();

        let deserialized: StringPool<u32> =
            bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.get(0), Some("foo"));
        assert_eq!(deserialized.get(1), Some("bar"));
        assert_eq!(deserialized.get(2), None);
    }

    #[test]
    fn bstring_pool_serde() {
        let mut pool: BStringPool<u32> = BStringPool::new();

        pool.get_or_intern("foo");
        pool.get_or_intern("bar");

        let serialized = bincode::serialize(&pool).unwrap();

        let deserialized: BStringPool<u32> =
            bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.get(0), Some(BStr::new("foo")));
        assert_eq!(deserialized.get(1), Some(BStr::new("bar")));
        assert_eq!(deserialized.get(2), None);
    }
}

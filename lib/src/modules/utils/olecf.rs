use crate::modules::olecf::parser::Olecf;

pub(crate) enum CachedOlecf<'a> {
    NotOlecf,
    Olecf(Olecf<&'a [u8]>),
}

impl<'a> CachedOlecf<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        match Olecf::parse(data) {
            Ok(olecf) => CachedOlecf::Olecf(olecf),
            Err(_) => CachedOlecf::NotOlecf,
        }
    }
}

use std::io;
use thiserror::Error;

/// Errors returned by [`Dumper::dump`].
#[derive(Error, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Error {
    /// Error while reading from input.
    #[error("Read error")]
    ReadError(io::Error),
}

/// Dumps information about binary files.
pub struct Dumper {}

impl Default for Dumper {
    fn default() -> Self {
        Self::new()
    }
}

// Dumper public API.
impl Dumper {
    /// Creates a new dumper.
    pub fn new() -> Self {
        Dumper {}
    }

    pub fn dump<R>(&self, mut input: R) -> Result<(), Error>
    where
        R: io::Read,
    {
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer).map_err(Error::ReadError)?;
        println!("Buffer: {:?}", buffer);
        Ok(())
    }
}

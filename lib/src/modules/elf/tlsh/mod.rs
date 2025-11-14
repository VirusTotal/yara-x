/*! Module for computing the Trend Micro Locality Sensitive Hash (TLSH)
   of a byte stream.

   This code has been taken from:
   <https://github.com/Uinelj/tlsh-rs>

   Which in turns is a clone of:
   <https://github.com/qy513314/tlsh-rs>

   As both repositories are mostly unmaintained, and the code is small,
   I've made a copy of it instead of taking a dependency.
*/

use std::str::FromStr;
mod error;
mod helper;
mod tests;

use error::TlshError;
use helper::{
    bit_distance, find_quartiles, l_capturing, mod_diff, pearson_hash,
    BUCKET_SIZE, WINDOW_SIZE,
};

const BUCKETS_A: [BucketKind; 2] =
    [BucketKind::Bucket128, BucketKind::Bucket256];
const CHECKSUM_A: [ChecksumKind; 2] =
    [ChecksumKind::OneByte, ChecksumKind::ThreeByte];
const VERSION_A: [Version; 2] = [Version::Original, Version::Version4];

/// A struct containing all required information from an input stream to
/// generate a hash value.
///
/// An instance of this struct can be obtained by calling the function
/// [`TlshBuilder::build`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tlsh {
    bucket_kind: BucketKind,
    checksum_kind: ChecksumKind,
    ver: Version,
    checksum: Vec<u8>,
    len: usize,
    q1ratio: usize,
    q2ratio: usize,
    codes: Vec<u8>,
}

impl Tlsh {
    /// Computes and returns the hash value in hex-encoded string format.
    pub fn hash(&self) -> String {
        let cap = hash_len(self.bucket_kind, self.checksum_kind, self.ver);
        let mut result = String::with_capacity(cap);
        result.push_str(self.ver.ver());

        for ii in 0..self.checksum.len() {
            result.push_str(
                &format!("{:02X}", self.checksum[ii])
                    .chars()
                    .rev()
                    .collect::<String>(),
            );
        }
        result.push_str(
            &format!("{:02X}", self.len as u32)
                .chars()
                .rev()
                .collect::<String>(),
        );
        result.push_str(&format!("{:02X}", self.q1ratio << 4 | self.q2ratio));

        let len = self.codes.len();
        for ii in 0..len {
            result.push_str(&format!("{:02X}", self.codes[len - 1 - ii]));
        }

        result
    }

    /// Calculates the difference between two TLSH values.
    ///
    /// ```with_len``` controls whether the difference in length should be also
    /// considered in the calculation.
    pub fn diff(&self, other: &Tlsh, with_len: bool) -> usize {
        let mut result = 0;

        if with_len {
            match mod_diff(self.len, other.len, 256) {
                x @ 0..=1 => result = x,
                x => result = x * 12,
            };
        }

        match mod_diff(self.q1ratio, other.q1ratio, 16) {
            x @ 0..=1 => result += x,
            x => result += (x - 1) * 12,
        }

        match mod_diff(self.q2ratio, other.q2ratio, 16) {
            x @ 0..=1 => result += x,
            x => result += (x - 1) * 12,
        }

        for ii in 0..self.checksum.len() {
            if self.checksum[ii] != other.checksum[ii] {
                result += 1;
                break;
            }
        }

        result += bit_distance(&self.codes, &other.codes);
        result
    }
}

impl FromStr for Tlsh {
    type Err = TlshError;
    /// Try to convert a hash string. Returns an instance of [`Tlsh`] if the
    /// conversion is successful.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mut bucket_kind, mut checksum_kind, mut ver) = (None, None, None);

        'outer: for bk in &BUCKETS_A {
            for ck in &CHECKSUM_A {
                for v in &VERSION_A {
                    if s.len() == hash_len(*bk, *ck, *v) {
                        bucket_kind = Some(*bk);
                        checksum_kind = Some(*ck);
                        ver = Some(*v);
                        break 'outer;
                    }
                }
            }
        }

        if bucket_kind.is_none() {
            Err(TlshError::InvalidHashValue)?
        }

        let mut offset = ver.unwrap().ver().len();
        let mut checksum = vec![0; checksum_kind.unwrap().checksum_len()];
        let mut codes = vec![0; bucket_kind.unwrap().bucket_count() >> 2];

        for item in &mut checksum {
            *item = u8::from_str_radix(
                &s[offset..(offset + 2)].chars().rev().collect::<String>(),
                16,
            )?;
            offset += 2;
        }

        let len = usize::from_str_radix(
            &s[offset..(offset + 2)].chars().rev().collect::<String>(),
            16,
        )?;
        offset += 2;

        let qratio: usize =
            usize::from_str_radix(&s[offset..(offset + 2)], 16)?;
        offset += 2;

        let clen = codes.len();

        for ii in 0..clen {
            codes[clen - ii - 1] =
                u8::from_str_radix(&s[offset..(offset + 2)], 16)?;
            offset += 2;
        }

        Ok(Self {
            bucket_kind: bucket_kind.unwrap(),
            checksum_kind: checksum_kind.unwrap(),
            ver: ver.unwrap(),
            checksum,
            len,
            q1ratio: qratio >> 4,
            q2ratio: qratio & 0xF,
            codes,
        })
    }
}
/// A builder struct for processing input stream(s).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TlshBuilder {
    bucket_kind: BucketKind,
    checksum_kind: ChecksumKind,
    buckets: [u32; BUCKET_SIZE],
    bucket_count: usize,
    checksum: u8,
    checksum_array: Vec<u8>,
    checksum_len: usize,
    code_size: usize,
    data_len: usize,
    slide_window: [u8; WINDOW_SIZE],
    ver: Version,
}

impl TlshBuilder {
    /// Constructs a new builder based on the number of buckets, checksum length and version.
    pub fn new(
        bucket: BucketKind,
        checksum: ChecksumKind,
        ver: Version,
    ) -> Self {
        let bucket_count = bucket.bucket_count();
        let checksum_len = checksum.checksum_len();

        Self {
            bucket_kind: bucket,
            checksum_kind: checksum,
            buckets: [0; BUCKET_SIZE],
            bucket_count,
            checksum: 0,
            checksum_array: vec![0; checksum_len],
            checksum_len,
            code_size: bucket_count >> 2,
            data_len: 0,
            slide_window: [0; WINDOW_SIZE],
            ver,
        }
    }

    /// Computes the quartiles and constructs the digest message and returns
    /// an instance of [`Tlsh`] that has all information needed to generate a
    /// hash value.
    pub fn build(&self) -> Result<Tlsh, TlshError> {
        if self.data_len < 50 {
            Err(TlshError::MinSizeNotReached)?
        }

        let (q1, q2, q3) = find_quartiles(&self.buckets, self.bucket_count);

        if q3 == 0 {
            Err(TlshError::NoValidHash)?
        }

        let mut tmp = vec![0; self.code_size];

        for (ii, item) in tmp.iter_mut().enumerate() {
            let mut h = 0;

            for jj in 0..4 {
                // Out of bound check?
                let kk = self.buckets[4 * ii + jj];
                if q3 < kk {
                    h += 3 << (jj * 2);
                } else if q2 < kk {
                    h += 2 << (jj * 2);
                } else if q1 < kk {
                    h += 1 << (jj * 2);
                }
            }

            *item = h;
        }

        let len = l_capturing(self.data_len)?;
        let q1ratio = (((q1 as f64 * 100.) / (q3 as f64)) as usize) % 16;
        let q2ratio = (((q2 as f64 * 100.) / (q3 as f64)) as usize) % 16;

        let checksum = if self.checksum_len == 1 {
            vec![self.checksum]
        } else {
            self.checksum_array.clone()
        };

        Ok(Tlsh {
            bucket_kind: self.bucket_kind,
            checksum_kind: self.checksum_kind,
            ver: self.ver,
            checksum,
            len,
            q1ratio,
            q2ratio,
            codes: tmp,
        })
    }

    /// Processes an input stream.
    pub fn update(&mut self, data: &[u8]) {
        self.update_from(data, 0, data.len());
    }

    /// Reads an input stream from an offset and processes it.
    ///
    /// # Parameters
    /// * data: input data to be added
    /// * offset: index in array from which data will be read
    /// * len: number of bytes to be read
    pub fn update_from(&mut self, data: &[u8], offset: usize, len: usize) {
        let mut j0 = self.data_len % WINDOW_SIZE;
        let (mut j1, mut j2, mut j3, mut j4) = (
            (j0 + WINDOW_SIZE - 1) % WINDOW_SIZE,
            (j0 + WINDOW_SIZE - 2) % WINDOW_SIZE,
            (j0 + WINDOW_SIZE - 3) % WINDOW_SIZE,
            (j0 + WINDOW_SIZE - 4) % WINDOW_SIZE,
        );

        let mut fed_len = self.data_len;

        for item in data.iter().skip(offset).take(len) {
            self.slide_window[j0] = *item;

            if fed_len >= 4 {
                self.checksum = pearson_hash(
                    0,
                    self.slide_window[j0],
                    self.slide_window[j1],
                    self.checksum,
                );

                if self.checksum_len > 1 {
                    self.checksum_array[0] = self.checksum;

                    for kk in 1..self.checksum_len {
                        self.checksum_array[kk] = pearson_hash(
                            self.checksum_array[kk - 1],
                            self.slide_window[j0],
                            self.slide_window[j1],
                            self.checksum_array[kk],
                        )
                    }
                }

                // Select 6 triplets out of 10. The last four are processed in
                // the next iteration.
                // A  - B   - C  - D  - E
                // j0   j1    j2   j3   j4

                let mut r = pearson_hash(
                    2,
                    self.slide_window[j0],
                    self.slide_window[j1],
                    self.slide_window[j2],
                );
                self.buckets[r as usize] += 1;

                r = pearson_hash(
                    3,
                    self.slide_window[j0],
                    self.slide_window[j1],
                    self.slide_window[j3],
                );
                self.buckets[r as usize] += 1;

                r = pearson_hash(
                    5,
                    self.slide_window[j0],
                    self.slide_window[j2],
                    self.slide_window[j3],
                );
                self.buckets[r as usize] += 1;

                r = pearson_hash(
                    7,
                    self.slide_window[j0],
                    self.slide_window[j2],
                    self.slide_window[j4],
                );
                self.buckets[r as usize] += 1;

                r = pearson_hash(
                    11,
                    self.slide_window[j0],
                    self.slide_window[j1],
                    self.slide_window[j4],
                );
                self.buckets[r as usize] += 1;

                r = pearson_hash(
                    13,
                    self.slide_window[j0],
                    self.slide_window[j3],
                    self.slide_window[j4],
                );
                self.buckets[r as usize] += 1;
            }

            fed_len += 1;

            let tmp = j4;

            j4 = j3;
            j3 = j2;
            j2 = j1;
            j1 = j0;
            j0 = tmp;
        }

        self.data_len += len;
    }
}

/// An enum determining the number of buckets for hashing.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum BucketKind {
    /// Hashing with 128 buckets.
    Bucket128,
    /// Hashing with 256 buckets.
    Bucket256,
}

impl BucketKind {
    /// Returns the number of buckets.
    pub fn bucket_count(&self) -> usize {
        match self {
            BucketKind::Bucket128 => 128,
            BucketKind::Bucket256 => 256,
        }
    }
}

/// An enum determining the length of checksum.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum ChecksumKind {
    /// TLSH uses one byte for checksum. The collision rate is 1/24.
    OneByte,
    /// TLSH uses three bytes for checksum. The collision rate is 1/5800.
    ThreeByte,
}

impl ChecksumKind {
    pub fn checksum_len(&self) -> usize {
        match self {
            ChecksumKind::OneByte => 1,
            ChecksumKind::ThreeByte => 3,
        }
    }
}

/// An enum representing the version of TLSH.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Version {
    /// Original version, mapping to an empty string ```""```.
    Original,
    /// Current version, mapping to a string ```"T1"```.
    Version4,
}

impl Version {
    pub fn ver(&self) -> &str {
        match self {
            Version::Original => "",
            Version::Version4 => "T1",
        }
    }
}

fn hash_len(
    bucket: BucketKind,
    checksum: ChecksumKind,
    ver: Version,
) -> usize {
    (bucket.bucket_count() >> 1)
        + (checksum.checksum_len() << 1)
        + ver.ver().len()
        + 4
}

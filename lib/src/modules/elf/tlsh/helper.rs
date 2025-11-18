use super::error::TlshError;
use std::cmp::Ordering::{Equal, Greater, Less};
use std::ops::{Add, Sub};

pub(crate) const BUCKET_SIZE: usize = 256;
/// Size of a sliding window to process a byte string and populate an array of bucket counts.
pub(crate) const WINDOW_SIZE: usize = 5;

pub(crate) const V_TABLE: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14,
    197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110,
    177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222, 25,
    107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235, 97,
    234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248, 174,
    169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243, 132,
    56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10, 138,
    30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152, 170, 7,
    115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131, 125, 173,
    15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123, 118, 73,
    2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229, 27, 188,
    67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203, 233, 40,
    186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76, 140,
    36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120, 51,
    65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
];

pub(crate) const TOPVAL: [usize; 170] = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110,
    1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772,
    7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970, 17567, 19323,
    21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564, 50121,
    55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002,
    143002, 157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538,
    337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800,
    795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534, 1549388,
    1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252,
    3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394,
    7831333, 8614467, 9475909, 10423501, 11465851, 12612437, 13873681,
    15261050, 16787154, 18465870, 20312458, 22343706, 24578077, 27035886,
    29739474, 32713425, 35984770, 39583245, 43541573, 47895730, 52685306,
    57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779,
    112935659, 124229227, 136652151, 150317384, 165349128, 181884040,
    200072456, 220079703, 242087671, 266296456, 292926096, 322218735,
    354440623, 389884688, 428873168, 471760495, 518936559, 570830240,
    627913311, 690704607, 759775136, 835752671, 919327967, 1011260767,
    1112386880, 1223623232, 1345985727, 1480584256, 1628642751, 1791507135,
    1970657856, 2167723648, 2384496256, 2622945920, 2885240448, 3173764736,
    3491141248, 3840255616, 4224281216,
];

const _MAX_DATA_LEN: usize = TOPVAL[TOPVAL.len() - 1];

static mut BIT_PAIRS_FLAG: bool = false;
static mut BIT_PAIRS_DIFF: [[usize; 256]; 256] = [[0; 256]; 256];

pub(crate) fn pearson_hash(salt: u8, ii: u8, jj: u8, kk: u8) -> u8 {
    let mut h = 0;

    h = V_TABLE[(h ^ salt) as usize];
    h = V_TABLE[(h ^ ii) as usize];
    h = V_TABLE[(h ^ jj) as usize];
    h = V_TABLE[(h ^ kk) as usize];

    h
}

pub(crate) fn find_quartiles(
    buckets: &[u32],
    bucket_count: usize,
) -> (u32, u32, u32) {
    let mut buckets_copy: Vec<u32> = buckets[0..bucket_count].to_vec();
    let (mut shortcut_low, mut shortcut_high) =
        (vec![0; bucket_count], vec![0; bucket_count]);
    let (mut spl, mut sph) = (0, 0);

    let quartile = bucket_count >> 2;
    let p1 = quartile - 1;
    let p2 = p1 + quartile;
    let p3 = p2 + quartile;
    let end = p3 + quartile;

    // Applies quicksort to find p2
    let (mut low, mut high) = (0, end);
    let q2 = loop {
        let pivot = partition(&mut buckets_copy, low, high);

        match pivot.cmp(&p2) {
            Greater => {
                high = pivot - 1;
                shortcut_high[sph] = pivot;
                sph += 1;
            }
            Less => {
                low = pivot + 1;
                shortcut_low[spl] = pivot;
                spl += 1;
            }

            Equal => {
                break buckets_copy[p2];
            }
        }
    };

    shortcut_low[spl] = p2 - 1;
    shortcut_high[sph] = p2 + 1;

    let mut q1 = 0;
    low = 0;
    //for ii in 0..spl {
    for item in shortcut_low.iter().take(spl) {
        high = *item;

        match high.cmp(&p1) {
            Greater => {
                q1 = loop {
                    let pivot = partition(&mut buckets_copy, low, high);
                    match pivot.cmp(&p1) {
                        Greater => high = pivot - 1,
                        Less => low = pivot + 1,
                        Equal => break buckets_copy[p1],
                    }
                };
                break;
            }
            Less => {
                low = high;
            }
            Equal => {
                q1 = buckets_copy[p1];
                break;
            }
        }
    }

    let mut q3 = 0;
    high = end;
    for item in shortcut_high.iter().take(sph) {
        low = *item;
        match low.cmp(&p3) {
            Less => {
                q3 = loop {
                    let pivot = partition(&mut buckets_copy, low, high);
                    match pivot.cmp(&p3) {
                        Less => low = pivot + 1,
                        Greater => high = pivot - 1,
                        Equal => break buckets_copy[p3],
                    }
                };
                break;
            }

            Equal => {
                q3 = buckets_copy[p3];
                break;
            }

            Greater => high = low,
        }
    }

    (q1, q2, q3)
}

pub(crate) fn partition(
    buckets: &mut [u32],
    low: usize,
    high: usize,
) -> usize {
    if low == high {
        return low;
    }

    if low + 1 == high {
        if buckets[low] > buckets[high] {
            buckets.swap(low, high);
        }

        return low;
    }

    let (mut result, pivot) = (low, (low + high) >> 1);
    let val = buckets[pivot];
    buckets.swap(pivot, high);

    for ii in low..high {
        if buckets[ii] < val {
            buckets.swap(ii, result);
            result += 1;
        }
    }

    buckets[high] = buckets[result];
    buckets[result] = val;

    result
}

pub(crate) fn mod_diff<T>(x: T, y: T, circ_q: T) -> T
where
    T: Copy + PartialEq + Ord + Add<Output = T> + Sub<Output = T>,
{
    let (dl, dr) =
        if x >= y { (x - y, y + circ_q - x) } else { (y - x, x + circ_q - y) };

    std::cmp::min(dl, dr)
}

pub(crate) fn bit_distance(x: &[u8], y: &[u8]) -> usize {
    let mut result = 0;

    for ii in 0..x.len() {
        unsafe {
            result += bit_pairs_diff(x[ii] as usize, y[ii] as usize);
        }
    }

    result
}

#[inline]
unsafe fn bit_pairs_diff(row: usize, col: usize) -> usize {
    let f = |x: &mut i16, y: &mut i16, diff: &mut i16| {
        let d = (*x % 4 - *y % 4).abs();
        *diff += if d == 3 { 6 } else { d };

        *x /= 4;
        *y /= 4;
    };

    if !BIT_PAIRS_FLAG {
        for ii in 0..256i16 {
            for jj in 0..256 {
                let (mut x, mut y, mut diff) = (ii, jj, 0);
                for _ in 0..4 {
                    f(&mut x, &mut y, &mut diff);
                }

                BIT_PAIRS_DIFF[ii as usize][jj as usize] = diff as usize;
            }
        }
        BIT_PAIRS_FLAG = true;
    }

    BIT_PAIRS_DIFF[row][col]
}

pub(crate) fn l_capturing(len: usize) -> Result<usize, TlshError> {
    let (mut top, mut bottom) = (TOPVAL.len(), 0);
    let mut idx = top >> 1;

    while idx < TOPVAL.len() {
        if idx == 0 {
            return Ok(idx);
        }

        if len <= TOPVAL[idx] && len > TOPVAL[idx - 1] {
            return Ok(idx);
        }

        if len < TOPVAL[idx] {
            top = idx - 1;
        } else {
            bottom = idx + 1;
        }

        idx = (bottom + top) >> 1;
    }

    Err(TlshError::DataLenOverflow)
}

//! Reference hashing.
//!
//! Port of unidbg: `unidbg-android/src/main/java/com/github/unidbg/linux/android/dvm/{Hasher,Hashable}.java`
//! @7f5da98e.
//!
//! unidbg has no DEX interpreter: a `jobject`/`jclass`/`jmethodID`/`jfieldID` is
//! a 32-bit *hash* of a name, and the maps from hash to object are the whole
//! Java side. The hasher is selectable because applications that depend on a
//! particular `jmethodID` value need the same one unidbg used.

use std::hash::Hasher as _;

/// How a name is turned into a reference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Hasher {
    /// unidbg's default: `java.util.HashMap`'s string hash.
    #[default]
    Default,
    /// FNV-1a.
    Fnv1a,
    /// MurmurHash3 x86 32-bit.
    Murmur3,
    /// xxHash32.
    XxHash,
}

impl Hasher {
    /// Hashes `value`.
    pub fn hash(&self, value: &str) -> i32 {
        match self {
            Hasher::Default => java_string_hash(value),
            Hasher::Fnv1a => fnv1a(value),
            Hasher::Murmur3 => murmur3(value),
            Hasher::XxHash => xxhash32(value),
        }
    }
}

/// `java.lang.String.hashCode`: `s[0]*31^(n-1) + ... + s[n-1]`.
pub fn java_string_hash(value: &str) -> i32 {
    let mut hash: i32 = 0;
    for unit in value.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(i32::from(unit));
    }
    hash
}

fn fnv1a(value: &str) -> i32 {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash as i32
}

fn murmur3(value: &str) -> i32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let data = value.as_bytes();
    let mut hash: u32 = 0;
    for chunk in data.chunks_exact(4) {
        let mut k = u32::from_le_bytes(chunk.try_into().expect("four bytes"));
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        hash ^= k;
        hash = hash.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = data.len() % 4;
    if tail > 0 {
        let mut k: u32 = 0;
        for (index, byte) in data[data.len() - tail..].iter().enumerate() {
            k |= u32::from(*byte) << (8 * index);
        }
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        hash ^= k;
    }
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^= hash >> 16;
    hash as i32
}

fn xxhash32(value: &str) -> i32 {
    /// xxHash32's prime constants.
    const P1: u32 = 0x9e37_79b1;
    const P2: u32 = 0x85eb_ca77;
    const P3: u32 = 0xc2b2_ae3d;
    const P4: u32 = 0x27d4_eb2f;
    const P5: u32 = 0x1656_67b1;

    let data = value.as_bytes();
    let mut hash: u32;
    let mut cursor = 0usize;
    if data.len() >= 16 {
        let mut accumulators = [
            P1.wrapping_add(P2),
            P2,
            0u32,
            0u32.wrapping_sub(P1),
        ];
        for (index, chunk) in data.chunks_exact(16).enumerate() {
            accumulators[index % 4] = round(
                accumulators[index % 4],
                u32::from_le_bytes(chunk[..4].try_into().expect("four bytes")),
            );
            accumulators[(index + 1) % 4] = round(
                accumulators[(index + 1) % 4],
                u32::from_le_bytes(chunk[4..8].try_into().expect("four bytes")),
            );
            accumulators[(index + 2) % 4] = round(
                accumulators[(index + 2) % 4],
                u32::from_le_bytes(chunk[8..12].try_into().expect("four bytes")),
            );
            accumulators[(index + 3) % 4] = round(
                accumulators[(index + 3) % 4],
                u32::from_le_bytes(chunk[12..].try_into().expect("four bytes")),
            );
        }
        cursor = data.len() / 16 * 16;
        hash = accumulators[0]
            .rotate_left(1)
            .wrapping_add(accumulators[1].rotate_left(7))
            .wrapping_add(accumulators[2].rotate_left(12))
            .wrapping_add(accumulators[3].rotate_left(18));
    } else {
        hash = P5;
    }
    hash = hash.wrapping_add(data.len() as u32);
    while cursor + 4 <= data.len() {
        let word = u32::from_le_bytes(data[cursor..cursor + 4].try_into().expect("four bytes"));
        hash = hash
            .wrapping_add(word.wrapping_mul(P3))
            .rotate_left(17)
            .wrapping_mul(P4);
        cursor += 4;
    }
    while cursor < data.len() {
        hash = hash
            .wrapping_add(u32::from(data[cursor]).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
        cursor += 1;
    }
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(P3);
    hash ^= hash >> 16;
    hash as i32
}

fn round(accumulator: u32, input: u32) -> u32 {
    const P1: u32 = 0x9e37_79b1;
    const P2: u32 = 0x85eb_ca77;
    accumulator
        .wrapping_add(input.wrapping_mul(P2))
        .rotate_left(13)
        .wrapping_mul(P1)
}

/// A type that has a reference hash, as unidbg's `Hashable` does.
pub trait Hashable {
    /// The value the hash is taken over.
    fn hash_value(&self) -> &str;

    /// The hash, under `hasher`.
    fn hash_code(&self, hasher: Hasher) -> i32 {
        hasher.hash(self.hash_value())
    }
}

/// A stable identity hash for a host object, as `System.identityHashCode` gives
/// unidbg's `DvmObject`s.
pub fn identity_hash<T: ?Sized>(value: &T) -> i32 {
    let address = value as *const T as *const () as usize;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write_usize(address);
    hasher.finish() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_hasher_matches_java_string_hash_code() {
        // From the JLS: "a".hashCode() == 97, "abc".hashCode() == 96354.
        assert_eq!(java_string_hash("a"), 97);
        assert_eq!(java_string_hash("abc"), 96354);
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(Hasher::Default.hash("abc"), 96354);
    }

    #[test]
    fn the_other_hashers_are_stable_and_distinct() {
        let value = "Lcom/raxdbg/test/JniTest;->add(II)I";
        let hashes: Vec<i32> = [
            Hasher::Default,
            Hasher::Fnv1a,
            Hasher::Murmur3,
            Hasher::XxHash,
        ]
        .iter()
        .map(|hasher| hasher.hash(value))
        .collect();
        // Deterministic.
        for (index, hasher) in [
            Hasher::Default,
            Hasher::Fnv1a,
            Hasher::Murmur3,
            Hasher::XxHash,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(hasher.hash(value), hashes[index]);
        }
        // And they disagree, which is why the choice is the caller's.
        let mut sorted = hashes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert!(sorted.len() >= 3, "{hashes:?}");
    }

    #[test]
    fn murmur3_matches_its_published_vector() {
        // MurmurHash3 x86_32 of the empty string with seed 0 is 0.
        assert_eq!(murmur3(""), 0);
        // And of "hello" it is 0x248bfa47.
        assert_eq!(murmur3("hello") as u32, 0x248b_fa47);
    }

    #[test]
    fn xxhash32_matches_its_published_vector() {
        // xxHash32 of "" with seed 0 is 0x02cc5d05.
        assert_eq!(xxhash32("") as u32, 0x02cc_5d05);
    }
}

// Below is code originally from https://github.com/Mubelotix/dkim
// We give up using a fork because the dependency is somewhat old.

use alloc::vec::Vec;
pub fn body_hash_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn data_hash_sha256(headers: &[u8], dkim_header: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(headers);
    hasher.update(dkim_header);
    hasher.finalize().to_vec()
}
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use core::result::Result;

use bitvec::prelude::BitSlice;

pub fn get_root<HashType>(
    key: &BitSlice,
    leaf_hash: HashType,
    proof: Vec<HashType>,
    hash_fn: (fn(&[u8]) -> HashType),
) -> Result<HashType, &'static str>
    where
        HashType: AsRef<[u8]>,
{
    // Validate key size to proof size
    if key.len() != proof.len() { // Sanity check that sizes match
        return Err("Key must be the same size as the proof!");
    }

    // Start result at leaf
    let mut node_hash = leaf_hash;

    // Path is the bits of key in leaf->root order (MSB to LSB), so reverse it!
    // Branch is in root->leaf order, so reverse it!
    for (is_right, sibling_node) in key.iter().rev().zip(proof.iter().rev()) {
        let node = if is_right {
            sibling_node.as_ref().iter()
                .chain(node_hash.as_ref().iter())
                .copied().collect::<Vec<u8>>()
        } else {
            node_hash.as_ref().iter()
                .chain(sibling_node.as_ref().iter())
                .copied().collect::<Vec<u8>>()
        };
        node_hash = (hash_fn)(node.as_slice());
    }
    Ok(node_hash)
}

// TODO Add SMT MerkleDB for txn trie inclusion/exclusion checks

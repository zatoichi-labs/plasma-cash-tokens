#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use core::result::Result;

#[cfg(not(feature = "std"))]
use core::convert::AsRef;

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

/// Tests generated using Python package `py-trie`, which contains a Sparse Merkle Tree
/// library created by the author and maintained by the Ethereum Foundation.
#[cfg(test)]
mod test {
    use super::*;

    use bitvec::prelude::*;
    use ethereum_types::H256;
    extern crate hex;
    use keccak_hash::keccak;

    fn hasher(input: &[u8]) -> H256 {
        keccak(input)
    }

    fn hex_to_h256(hexstr: &str) -> H256 {
        let bytes = hex::decode(hexstr).unwrap();
        let mut bytes32 = [0u8; 32];
        bytes32.copy_from_slice(bytes.as_ref());
        H256::from(bytes32)
    }

    #[test]
    fn mismatch_size_fails() {
        let key: u8 = 7;
        let key: &BitSlice = key.as_bitslice::<BigEndian>();
        let leaf_hash = hex_to_h256(
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let proof = vec![
            // Should be 8 nodes, not 1
            "0000000000000000000000000000000000000000000000000000000000000000",
        ].iter().map(|h| hex_to_h256(h)).collect::<Vec<H256>>();
        assert!(get_root(key, leaf_hash, proof, hasher).is_err());
    }

    #[test]
    /// `calc_root(b"\x07", EMPTY_BYTES32, [EMPTY_BYTES32] * 8)`
    fn depth_8_root_blank_node() {
        let key: u8 = 7;
        let key: &BitSlice = key.as_bitslice::<BigEndian>();
        let leaf_hash = hex_to_h256( // hash of empty bytes32
            "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
        );
        let proof = vec![
            "0000000000000000000000000000000000000000000000000000000000000008",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "0000000000000000000000000000000000000000000000000000000000000006",
            "0000000000000000000000000000000000000000000000000000000000000005",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ].iter().map(|h| hex_to_h256(h)).collect::<Vec<H256>>();
        let calculated_root = get_root(key, leaf_hash, proof, hasher).unwrap();
        let root = hex_to_h256(
            "1c0285e9d02f7aec67b4916dfe37254a507e00159bb4bb87a8511f9b6375f5ca"
        );
        assert_eq!(root, calculated_root);
    }
}

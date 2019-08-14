use alloc::vec::Vec;

use bitvec::prelude::BitSlice;

pub fn get_root<HashType>(
    key: &BitSlice,
    leaf_hash: HashType,
    proof: Vec<HashType>,
    hash_fn: (fn(&[u8]) -> HashType),
) -> HashType
    where
        HashType: AsRef<[u8]>,
{
    // Start result at leaf
    let mut node_hash = leaf_hash;

    // Path is the bits of key in leaf->root order (MSB to LSB)
    assert_eq!(key.len(), proof.len()); // Sanity check

    // Branch is in root->leaf order (so reverse it!)
    for (is_right, sibling_node) in key.iter().zip(proof.iter().rev()) {
        let node = if is_right {
            sibling_node.as_ref().iter()
                .chain(node_hash.as_ref().iter())
                .map(|a| *a).collect::<Vec<u8>>()
        } else {
            node_hash.as_ref().iter()
                .chain(sibling_node.as_ref().iter())
                .map(|a| *a).collect::<Vec<u8>>()
        };
        node_hash = (hash_fn)(node.as_slice());
    }
    node_hash
}

// TODO Add SMT MerkleDB for txn trie inclusion/exclusion checks

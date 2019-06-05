use bit_vec::BitVec;

extern crate ethereum_types;
pub use ethereum_types::{Address, U256, H256};

pub type HashFn = (fn(&[u8]) -> H256);

#[derive(Debug, PartialEq)]
pub enum TxnCmp {
    Same, // LHS & RHS are the same exact transaction
    Parent, // LHS is the parent of RHS
    Child, // RHS is the parent of LHS
    EarlierSibling, // LHS & RHS have same parent, but LHS is earlier
    LaterSibling, // LHS & RHS have same parent, but RHS is earlier
    DoubleSpend, // LHS & RHS are the same txn to two different receivers
    Unrelated, // LHS & RHS have no relationship to each other
}

/// Plasma Transactions form a DAG where only one pathway back is
/// considered legitimate. However, there may be multiple pathways,
/// so it is important to allow this behavior to be compared.
pub trait PlasmaCashTxn {

    /// Transaction is well-formed (implementation-specific)
    /// Note: This might be used for certain use-cases to verify proofs,
    ///       whereas other use cases might have only minimal verification.
    fn valid(&self) -> bool;

    /// Returns the "Leaf Hash" of this transaction, which may be the
    /// encoded transaction structure directly (and signed), or it may
    /// be the publicly accessible committment, as required for certain
    /// applications such as Zero Knowledge Proofs. Implementation is
    /// left up to the end user, but this must return a consistent hash
    /// for use in the Sparse Merkle Tree data structure that Plasma Cash
    /// is standardized around for it's key: value txn datastore.
    /// Note: Does *not* have to match the hash function used for SMT proofs
    fn leaf_hash(&self) -> H256;

    /// Returns an empty leaf hash. Used for proofs of exclusion in txn trie.
    fn empty_leaf_hash() -> H256;

    /// Returns the size (in bits) of the token uid. Used to traverse the
    /// Sparse Merkle Tree to the correct depth.
    fn key_size() -> usize;

    /// Function used to verify proofs
    fn hash_fn() -> HashFn;

    /// Simply gives the receiver of the transaction, if available.
    /// Note: This is a Convenience API. This info may not be public.
    ///       For example, use cases involving Zero Knowledge Proofs.
    ///       (In that scenario, only certain parties can see this.)
    fn receiver(&self) -> Option<Address>;

    /// Simply gives the sender of the transaction, if available.
    /// Note: This is a Convenience API. This info may not be public.
    ///       For example, use cases involving Zero Knowledge Proofs.
    ///       (In that scenario, only certain parties can see this.)
    fn sender(&self) -> Option<Address>;

    /// Returns the relationship of another transaction (RHS) to this
    /// one (LHS). See Enum definition for more information.
    /// Note: This is used in the history verification logic, as well as
    ///       withdrawal challenge detection.
    fn compare(&self, other: &Self) -> TxnCmp;
}

/// Validate ordered list of all transactions for a given token
pub fn is_history_valid<T: PlasmaCashTxn>(history: &[T]) -> bool {
    // If token has no history, return True
    if history.len() == 0 {
        return true;
    }

    // Ensure all transactions are invidiually well-formed
    if !history.iter().all(|txn| txn.valid()) {
        return false;
    }

    // History is valid if each txn is the child of the previous
    let mut history_iter = history.iter().peekable();
    while let Some(prev_txn) = history_iter.next() {
        if let Some(txn) = history_iter.peek() {
            match txn.compare(&prev_txn) {
                TxnCmp::Child => { },
                _ => { return false },
            }
        }
    }

    true
}

pub struct MerkleProof {
    pub proof: Vec<H256>,
}

impl MerkleProof {

    /// Obtain the root hash following the SMT algorithm
    /// Note: Proof is in un-compressed form
    pub fn get_root(&self,
                    key: U256,
                    key_size: usize,
                    leaf_hash: H256,
                    hash_fn: HashFn,
                    ) -> H256 {
        let mut node_hash = leaf_hash;
        // Path is in leaf->root order (MSB to LSB)
        let path = BitVec::from_fn(key_size, |i| key.bit(i)); // TODO ensure in correct order (LE or BE?)
        // Branch is in root->leaf order (so reverse it!)
        for (is_left, sibling_node) in path.iter().zip(self.proof.iter().rev()) {
            let mut node = Vec::with_capacity(512);
            if is_left {
                node = [sibling_node.as_bytes(), node_hash.as_bytes()].concat();
            } else {
                node = [node_hash.as_bytes(), sibling_node.as_bytes()].concat();
            }
            node_hash = (hash_fn)(&node);
        }
        node_hash
    }
}

pub fn validate_root_hash<T>(plasma_root_hash: H256,
                             uid: U256,
                             txn: Option<&T>,
                             proof: &MerkleProof,
                             ) -> bool
    where T: PlasmaCashTxn
{
    let leaf_hash = match txn {
        Some(txn) => txn.leaf_hash(),
        None => T::empty_leaf_hash(),
    };

    let key_size = T::key_size();

    plasma_root_hash == proof.get_root(uid, key_size, leaf_hash, T::hash_fn())
}

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

pub struct Token<'a, T: PlasmaCashTxn> {
    pub uid: U256, // Key for Sparse Merkle Tree datastore
    pub status: TokenStatus, // Convenience API
    pub history: Vec<T>, // List of transactions
    pub proofs: Vec<(H256, Option<&'a T>, MerkleProof)>, // List of proof data
}

impl<'a, T: PlasmaCashTxn> Token<'a, T> {
    pub fn new(uid: U256) -> Token<'a, T> {
        Token {
            uid,
            status: TokenStatus::RootChain,
            history: Vec::new(),
            proofs: Vec::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let proof_data_matches =
                self.proofs.iter().all(|(r, t, p)| {
                    validate_root_hash(*r, self.uid, *t, p)
                });

        is_history_valid(&self.history)
        && proof_data_matches
    }

    pub fn add_transaction(&mut self, txn: T) {
        if self.history.len() > 0 {
            assert_eq!(txn.compare(self.history.last().unwrap()), TxnCmp::Parent);
        }
        self.history.push(txn);
    }

    pub fn owner(&self) -> Address {
        // TODO Call out to Web3 instead if in the RootChain
        self.history.last().unwrap().receiver().unwrap()
    }
}

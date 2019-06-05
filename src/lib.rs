use bit_vec::BitVec;

extern crate ethereum_types;
pub use ethereum_types::{Address, U256, H256};


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
    fn leaf_hash(&self) -> H256;

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
            match prev_txn.compare(&txn) {
                TxnCmp::Parent => { },
                _ => { return false },
            }
        }
    }

    true
}

pub struct MerkleProof {
    pub proof: Vec<H256>,
}

// TODO Make this a generic hashing function
extern crate keccak_hash;
use keccak_hash::keccak;

impl MerkleProof {

    /// Obtain the root hash following the SMT algorithm
    /// Note: Proof is in un-compressed form
    pub fn root(&self, key: U256, leaf_hash: H256) -> H256 {
        let mut node = leaf_hash;
        let path = BitVec::from_fn(256, |i| key.bit(i)); // TODO ensure in correct order
        for (is_left, sibling_node) in path.iter().zip(self.proof.iter()) {
            if is_left {
                node = keccak([sibling_node.as_bytes(), node.as_bytes()].concat());
            } else {
                node = keccak([node.as_bytes(), sibling_node.as_bytes()].concat());
            }
        }
        node
    }
}

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

pub struct Token<T: PlasmaCashTxn> {
    pub uid: U256, // Key for Sparse Merkle Tree datastore
    pub status: TokenStatus, // Convenience API
    pub history: Vec<T>,
}

impl<T: PlasmaCashTxn> Token<T> {
    pub fn new(uid: U256) -> Token<T> {
        Token {
            uid,
            status: TokenStatus::RootChain,
            history: Vec::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        is_history_valid(&self.history)
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

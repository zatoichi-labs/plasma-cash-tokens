use bit_vec::BitVec;


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
pub trait PlasmaCashTxn<UidType, HashType>
    where UidType: AsRef<[u64]>,
          HashType: AsRef<[u8]>
{
    /// Needed to obtain the key for a Merkle Proof
    fn token_id(&self) -> UidType;

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
    fn leaf_hash(&self) -> HashType;

    /// Returns an empty leaf hash. Used for proofs of exclusion in txn trie.
    fn empty_leaf_hash() -> HashType;

    /// Function used to verify proofs
    fn hash_fn() -> (fn(&[u8]) -> HashType);

    /// Returns the relationship of another transaction (RHS) to this
    /// one (LHS). See Enum definition for more information.
    /// Note: This is used in the history verification logic, as well as
    ///       withdrawal challenge detection.
    fn compare(&self, other: &Self) -> TxnCmp;

    /// Obtain the root hash following the SMT algorithm
    /// Note: Proof is in un-compressed form
    fn get_root(&self, proof: Vec<HashType>) -> HashType {
        get_root(self.token_id(), self.leaf_hash(), proof, Self::hash_fn())
    }
}

pub fn get_root<UidType, HashType>(
    key: UidType,
    leaf_hash: HashType,
    proof: Vec<HashType>,
    hash_fn: (fn(&[u8]) -> HashType),
) -> HashType
    where
        UidType: AsRef<[u64]>,
        HashType: AsRef<[u8]>,
{
    // Start result at leaf
    let mut node_hash = leaf_hash;

    // Path is the bits of key in leaf->root order (MSB to LSB)
    // TODO ensure in correct order (key is LE)
    let mut key_bytes: Vec<u8> = vec![];
    for key_word in key.as_ref().iter() {
        key_bytes.extend(&key_word.to_le_bytes());
    }
    let path = BitVec::from_bytes(&key_bytes);
    assert_eq!(path.len(), proof.len()); // Sanity check

    // Branch is in root->leaf order (so reverse it!)
    for (is_left, sibling_node) in path.iter().zip(proof.iter().rev()) {
        let node = if is_left {
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

/// Validate ordered list of all transactions for a given token
pub fn is_history_valid<TxnType, UidType, HashType>(
    history: &[TxnType],
) -> bool
    where
        TxnType: PlasmaCashTxn<UidType, HashType>,
        UidType: AsRef<[u64]>,
        HashType: AsRef<[u8]>,

{
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

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

pub struct Token<TxnType, UidType, HashType>
    where
        TxnType: PlasmaCashTxn,
        UidType: AsRef<[u64]>,
        HashType: AsRef<[u8]>
{
    pub uid: UidType, // Key for Sparse Merkle Tree datastore
    pub status: TokenStatus, // Convenience API
    pub history: Vec<TxnType>, // List of transactions
    pub proofs: Vec<Vec<HashType>>, // TODO Combine with history for complete inclusion/exclusion proofs
}

impl<TxnType, UidType, HashType> Token<TxnType, UidType, HashType>
    where
        TxnType: PlasmaCashTxn<UidType, HashType>,
        UidType: AsRef<[u64]>,
        HashType: AsRef<[u8]>
{
    pub fn new(uid: UidType) -> Token<TxnType, UidType, HashType> {
        Token {
            uid,
            status: TokenStatus::RootChain,
            history: Vec::new(),
            proofs: Vec::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        is_history_valid(&self.history)
    }

    pub fn add_transaction(&mut self, txn: TxnType) {
        if self.history.len() > 0 {
            assert_eq!(txn.compare(self.history.last().unwrap()), TxnCmp::Parent);
        }
        self.history.push(txn);
    }
}

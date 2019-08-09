use bitvec::prelude::BitVec;

use crate::merkle::get_root;

/// Returns the relationship of another transaction (RHS) to this one (LHS).
///
/// # Note
/// This is used in the history verification logic, as well as withdrawal
/// challenge detection logic. Different clients may have a privledged view
/// of this ordering, since transactions may be encrypted in some context and
/// unencrypted in others, which means relationships may differ depending on
/// information privledge of the client.
#[derive(Debug, PartialEq)]
pub enum TxnCmp {
    /// LHS & RHS are the same exact transaction
    Same,
    /// LHS is the parent of RHS
    Parent,
    /// RHS is the parent of LHS
    Child,
    /// LHS & RHS have same parent, but LHS is earlier
    EarlierSibling,
    /// LHS & RHS have same parent, but RHS is earlier
    LaterSibling,
    /// LHS & RHS are the same txn to two different receivers
    DoubleSpend,
    /// LHS & RHS have no relationship to each other
    Unrelated,
}

/// Plasma Transactions form a DAG where only one pathway back is
/// considered legitimate. However, there may be multiple pathways,
/// so it is important to allow this behavior to be compared.
/// Note: Users of this API should should define this e.g.
/// ```ignore
/// struct Transaction { ... }
///
/// impl PlasmaCashTxn<H256> for Transaction { ... }
/// ```
pub trait PlasmaCashTxn<HashType>
    where
        HashType: AsRef<[u8]>,
{
    /// Needed to obtain the key for a Merkle Proof
    fn token_id(&self) -> BitVec;

    /// Transaction is well-formed (implementation-specific)
    /// Note: This might be used for certain use-cases to verify zk proofs,
    ///       whereas other use cases might have only signature validation.
    fn valid(&self) -> bool;

    /// Returns the "Leaf Hash" of this transaction, which may be the
    /// encoded transaction structure directly (and signed), or it may
    /// be the publicly accessible committment, as required for certain
    /// applications such as Zero Knowledge Proofs. Implementation is
    /// left up to the end user, but this must return a consistent hash
    /// for use in the Sparse Merkle Tree data structure that Plasma Cash
    /// is standardized around for it's key: value txn datastore.
    /// Note: Does *not* have to match the hash function used for SMT proofs,
    ///       but is not required to be different since the transaction must
    ///       be valid for the smt proof to work.
    // TODO Validate security proof
    fn leaf_hash(&self) -> HashType;

    /// Returns an empty leaf hash. Used for proofs of exclusion in txn trie.
    fn empty_leaf_hash() -> HashType;

    /// Function used to verify proofs
    fn hash_fn() -> (fn(&[u8]) -> HashType);

    /// Returns the relationship of another transaction (other) to this
    /// one (self). See TxnCmp enum definition for more information.
    fn compare(&self, other: &Self) -> TxnCmp;

    /// Obtain the root hash following the SMT algorithm
    /// Note: Proof must be in un-compressed form (`proof.len() == smt.depth()`)
    fn get_root(&self, proof: Vec<HashType>) -> HashType {
        get_root(&self.token_id(), self.leaf_hash(), proof, Self::hash_fn())
    }
}

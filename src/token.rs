use bitvec::prelude::BitVec;

use crate::transaction::{PlasmaCashTxn, TxnCmp};

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

/// Token storage data type that performs history verification and challenge detection
/// for a given token. Can be serialized for wire transmission and data storage purposes.
/// Note: Users of this API should should define this e.g.
/// ```ignore
/// let t: Token<Transaction, H256> = Token::new(uid); // `uid` is BitVec
/// ```
pub struct Token<TxnType, HashType>
    where
        TxnType: PlasmaCashTxn<HashType>,
        HashType: AsRef<[u8]>,
{
    pub uid: BitVec, // Key for Sparse Merkle Tree datastore
    pub status: TokenStatus, // Convenience API
    pub history: Vec<TxnType>, // List of transactions
    pub proofs: Vec<Vec<HashType>>, // TODO Combine with history for complete inclusion/exclusion proofs
}

impl<'a, TxnType, HashType> Token<TxnType, HashType>
    where
        TxnType: PlasmaCashTxn<HashType>,
        HashType: AsRef<[u8]>,
{
    pub fn new(uid: BitVec) -> Token<TxnType, HashType> {
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
            assert_eq!(txn.compare(self.history.last().unwrap()), TxnCmp::Child);
        }
        self.history.push(txn);
    }
}

// Validate ordered list of all transactions for a given token
fn is_history_valid<TxnType, HashType>(
    history: &[TxnType],
) -> bool
    where
        TxnType: PlasmaCashTxn<HashType>,
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

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use core::result::Result;

use bitvec::prelude::BitVec;

use crate::transaction::{PlasmaCashTxn, TxnCmp};

/// Transfer and location status of the token.
#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    /// Token is freely transferrable on the Root Chain.
    RootChain,
    /// Token is in process of Deposit into the Child Chain.
    Deposit,
    /// Token is freely transferrable on the Child Chain.
    PlasmaChain,
    /// Token is in process of Withdrawal back to the Root Chain.
    Withdrawal,
}

/// Token storage type that performs history verification and challenge detection
/// for a given token.
///
/// Can be serialized for wire transmission and data storage purposes.
///
/// # Example
/// Users of this API should should define this e.g.
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
    /// Create new token with given uid stored on the rootchain.
    /// (history is empty to start)
    pub fn new(uid: BitVec) -> Token<TxnType, HashType> {
        Token {
            uid,
            status: TokenStatus::RootChain,
            history: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// Validate history of token is consistent
    pub fn is_valid(&self) -> bool {
        is_history_valid(&self.history)
    }

    /// Add a new transaction to the history. Must first pass validation
    /// that new transaction follows old one.
    pub fn add_transaction(&mut self, txn: TxnType) -> Result<(), &'static str> {
        match self.history.last() {
            Some(last_txn) if txn.compare(last_txn) != TxnCmp::Child =>
                Err("Transaction is not a child of previous transaction."),
            _ => {
                self.history.push(txn);
                Ok(())
            },
        }
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
    if history.is_empty() {
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

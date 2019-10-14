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
        TxnType: PlasmaCashTxn,
        HashType: AsRef<[u8]>,
{
    pub uid: BitVec, // Key for Sparse Merkle Tree datastore
    pub status: TokenStatus, // Convenience API
    pub history: Vec<TxnType>, // List of transactions
    pub proofs: Vec<Vec<HashType>>, // TODO Combine with history for complete inclusion/exclusion proofs
}

impl<TxnType, HashType> Token<TxnType, HashType>
    where
        TxnType: PlasmaCashTxn,
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
fn is_history_valid<TxnType>(
    history: &[TxnType],
) -> bool
    where
        TxnType: PlasmaCashTxn,

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

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;
    use std::mem::transmute;

    #[derive(PartialEq, Eq, Hash, Clone)]
    struct MockTransaction {
        token_id: BitVec,
        pub sender: u8,
        pub receiver: u8,
        pub block_num: u8,
    }

    impl MockTransaction {
        pub fn new(
            token_id: BitVec,
            sender: u8,
            receiver: u8,
            block_num: u8,
        ) -> Self {
            Self {
                token_id,
                sender,
                receiver,
                block_num,
            }
        }

        pub fn as_bytes(&self) -> [u8; 4] {
            let token_id: Vec<u8> = self.token_id.clone().into();
            [token_id[0], self.sender, self.receiver, self.block_num]
        }
    }

    impl PlasmaCashTxn for MockTransaction {
        type HashType = [u8; 8]; // Type returned by DefaultHasher

        fn token_id(&self) -> BitVec {
            self.token_id.clone()
        }

        fn hash_fn() -> (fn(&[u8]) -> Self::HashType) {
            | x: &[u8] | {
                let mut hasher = DefaultHasher::new();
                hasher.write(x);
                let result = hasher.finish();
                let result: [u8; 8] = unsafe { transmute(result.to_be()) };
                result
            }
        }

        fn empty_leaf_hash() -> Self::HashType {
            // Empty transaction
            let empty_leaf = MockTransaction::new(BitVec::from_element(0u8), 0, 0, 0);
            Self::hash_fn()(&empty_leaf.as_bytes())
        }

        fn leaf_hash(&self) -> Self::HashType {
            Self::hash_fn()(&self.as_bytes())
        }

        fn valid(&self) -> bool {
            true // All mocks are valid
        }

        fn compare(&self, other: &Self) -> TxnCmp {
            if self == other {
                return TxnCmp::Same;
            }

            if self.receiver == other.sender {
                return TxnCmp::Parent;
            }

            if self.sender == other.receiver {
                return TxnCmp::Child;
            }

            if self.sender == other.sender {
                if self.block_num < other.block_num {
                    return TxnCmp::EarlierSibling;
                }

                if self.block_num > other.block_num {
                    return TxnCmp::LaterSibling;
                }

                if self.block_num == other.block_num {
                    return TxnCmp::DoubleSpend;
                }
            }

            TxnCmp::Unrelated
        }
    }

    fn new_token(id: u8) -> Token<MockTransaction, [u8; 8]> {
        Token::new(BitVec::from_element(id))
    }

    #[test]
    fn test_add_transactions() {
        let mut t = new_token(1);
        assert!(t.is_valid());

        // Add three transactions in a row
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 0);
        assert!(t.add_transaction(txn1.clone()).is_ok());
        assert!(t.is_valid());

        let txn2 = MockTransaction::new(t.uid.clone(), 1, 2, 1);
        assert_eq!(txn1.compare(&txn2), TxnCmp::Parent);
        assert!(t.add_transaction(txn2).is_ok());
        assert!(t.is_valid());

        let txn3 = MockTransaction::new(t.uid.clone(), 2, 3, 2);
        assert!(t.add_transaction(txn3).is_ok());
        assert!(t.is_valid());
    }

    #[test]
    fn test_add_twice() {
        let mut t = new_token(1);
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 0);
        assert!(t.add_transaction(txn1.clone()).is_ok());

        // Try and add the same transaction twice
        assert_eq!(txn1.compare(&txn1), TxnCmp::Same);
        assert!(t.add_transaction(txn1).is_err());
        assert!(t.is_valid());
    }

    #[test]
    fn test_earlier_sibling() {
        let mut t = new_token(1);
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 1);
        assert!(t.add_transaction(txn1.clone()).is_ok());

        // Try and add a transaction sent before the stored one
        let txn2 = MockTransaction::new(t.uid.clone(), 0, 2, 0);
        assert_eq!(txn2.compare(&txn1), TxnCmp::EarlierSibling);
        assert!(t.add_transaction(txn2).is_err());
        assert!(t.is_valid());
    }

    #[test]
    fn test_later_sibling() {
        let mut t = new_token(1);
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 0);
        assert!(t.add_transaction(txn1.clone()).is_ok());

        // Try and add a transaction sent after the stored one that conflicts
        let txn2 = MockTransaction::new(t.uid.clone(), 0, 2, 1);
        assert_eq!(txn2.compare(&txn1), TxnCmp::LaterSibling);
        assert!(t.add_transaction(txn2).is_err());
        assert!(t.is_valid());
    }

    #[test]
    fn test_double_spend() {
        let mut t = new_token(1);
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 0);
        assert!(t.add_transaction(txn1.clone()).is_ok());

        // try and add a transaction that conflicts at the same height as the stored one
        let txn2 = MockTransaction::new(t.uid.clone(), 0, 2, 0);
        assert_eq!(txn2.compare(&txn1), TxnCmp::DoubleSpend);
        assert!(t.add_transaction(txn2).is_err());
        assert!(t.is_valid());
    }

    #[test]
    fn test_history_revision() {
        let mut t = new_token(1);
        let txn1 = MockTransaction::new(t.uid.clone(), 0, 1, 0);
        assert!(t.add_transaction(txn1.clone()).is_ok());

        // try and add a transaction that has no relationship to the stored one
        let txn2 = MockTransaction::new(t.uid.clone(), 2, 2, 1);
        assert_eq!(txn2.compare(&txn1), TxnCmp::Unrelated);
        assert!(t.add_transaction(txn2).is_err());
        assert!(t.is_valid());
    }
}

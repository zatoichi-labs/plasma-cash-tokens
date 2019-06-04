extern crate ethereum_types;
pub use ethereum_types::{Address, U256};

#[derive(Debug, PartialEq)]
pub enum TxnCmp {
    Same, // LHS == RHS
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
    /// Simply gives the receiver of the transaction, if available.
    /// Note: This info may not be public, e.g. Zero Knowledge Proofs
    ///       (In that scenario, only certain parties can see this.)
    fn receiver(&self) -> Option<Address>;

    /// Simply gives the sender of the transaction, if available.
    /// Note: This info may not be public, e.g. Zero Knowledge Proofs
    ///       (In that scenario, only certain parties can see this.)
    fn sender(&self) -> Option<Address>;

    /// Returns the relationship of another transaction (RHS) to this one (LHS)
    fn compare(&self, other: &Self) -> TxnCmp;
}

pub fn is_history_valid<T: PlasmaCashTxn>(history: &[T]) -> bool {
    // If token has no history, return True
    if history.len() == 0 {
        return true;
    }

    // History is valid if each transaction follows the previous
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

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

pub struct Token<T: PlasmaCashTxn> {
    pub uid: U256,
    pub status: TokenStatus,
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

#[cfg(test)]
mod test;

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
mod tests {
    extern crate rand;

    extern crate secp256k1;
    use secp256k1::{Secp256k1, Message, RecoverableSignature, key};

    extern crate keccak_hash;
    use keccak_hash::keccak;

    extern crate ethabi;

    fn pkey_to_address(pkey: &key::PublicKey) -> Address {
        let ctx = Secp256k1::new();
        let pkey_hash = keccak(pkey.serialize_vec(&ctx, false));
        Address::from_slice(&pkey_hash[..20])
    }

    // camelCase is used here because of EIP-712
    #[allow(non_snake_case)]
    pub struct Transaction {
        pub newOwner: Address,
        pub tokenId: U256,
        pub prevBlkNum: U256,
        signature: Option<RecoverableSignature>,
    }

    impl Transaction {
        // camelCase is used here because of EIP-712
        #[allow(non_snake_case)]
        pub fn new(newOwner: Address,
                   tokenId: U256,
                   prevBlkNum: U256) -> Transaction
        {
            Transaction {
                newOwner,
                tokenId,
                prevBlkNum,
                signature: None,
            }
        }

        // camelCase is used here because of EIP-712
        #[allow(non_snake_case)]
        pub fn new_signed(newOwner: Address,
                          tokenId: U256,
                          prevBlkNum: U256,
                          signature: RecoverableSignature) -> Transaction
        {
            Transaction {
                newOwner,
                tokenId,
                prevBlkNum,
                signature: Some(signature),
            }
        }

        pub fn unsigned_message(&self) -> Message {
            // Construct vector of Tokens
            let new_owner = ethabi::Token::Address(self.newOwner);
            let token_id = ethabi::Token::Uint(self.tokenId);
            let prev_blk_num = ethabi::Token::Uint(self.prevBlkNum);
            let msg_vec = &[new_owner, token_id, prev_blk_num];
            // Encode vector of Tokens
            let msg_bytes = ethabi::encode(msg_vec);
            // Return keccak hash of encoded struct
            Message::from_slice(keccak(msg_bytes).as_fixed_bytes()).unwrap()
        }

        pub fn sign(&self, skey: &key::SecretKey) -> Transaction {
            assert!(self.signature.is_none());
            let ctx = Secp256k1::new();
            let sig = ctx.sign_recoverable(&self.unsigned_message(), skey).unwrap();
            Transaction::new_signed(self.newOwner, self.tokenId, self.prevBlkNum, sig)
        }
    }

    impl PlasmaCashTxn for Transaction {
        fn receiver(&self) -> Option<Address> {
            Some(self.newOwner)
        }

        fn sender(&self) -> Option<Address> {
            let ctx = Secp256k1::new();
            let msg_hash = self.unsigned_message();
            let pkey = ctx.recover(&msg_hash, &self.signature.unwrap()).unwrap();
            Some(pkey_to_address(&pkey))
        }

        fn compare(&self, other: &Transaction) -> TxnCmp {

            // Transactions must be with the same tokenId to be related
            if self.tokenId == other.tokenId {

                // The other one is the direct parent of this one
                if self.newOwner == other.sender().unwrap() {
                    return TxnCmp::Parent; // FIXME Because this comes first, a cycle is possible

                // This one is the direct parent of the other one
                } else if self.sender().unwrap() == other.newOwner {
                    return TxnCmp::Child;

                // Both of us have the same parent
                } else if self.sender().unwrap() == other.sender().unwrap() {

                    // But mine comes before, so I'm earlier
                    if self.prevBlkNum < other.prevBlkNum {
                        return TxnCmp::EarlierSibling;

                    // The other comes before, so I'm later
                    } else if self.prevBlkNum > other.prevBlkNum {
                        return TxnCmp::LaterSibling;

                    // We're both at the same height, but different destinations!
                    } else if self.newOwner != other.newOwner {
                        return TxnCmp::DoubleSpend;
                    }

                    // We're both the same transaction (same tokenId, reciever, and sender)
                    return TxnCmp::Same;
                }
            }

            // All else fails, we're unrelated
            TxnCmp::Unrelated
        }
    }

    use super::*;

    fn gen_addr_and_skey_pair(data: &[u8]) -> (Address, key::SecretKey) {
        let ctx = Secp256k1::new();
        let skey = key::SecretKey::from_slice(&ctx, data).unwrap();
        let pkey = key::PublicKey::from_secret_key(&ctx, &skey).unwrap();
        let a = pkey_to_address(&pkey);
        (a, skey)
    }

    #[test]
    fn validate_empty_token() {
        let uid = U256::from(123);
        let t: Token<Transaction> = Token::new(uid);
        assert_eq!(t.uid, uid);
        assert_eq!(t.status, TokenStatus::RootChain);
        assert_eq!(t.history.len(), 0);
        assert!(t.is_valid());
    }

    #[test]
    fn add_transaction() {
        let (a, skey) = gen_addr_and_skey_pair(&[1; 32]);
        let uid = U256::from(123);
        let mut t: Token<Transaction> = Token::new(uid);
        let txn = Transaction::new(a, uid, U256::from(0)).sign(&skey);

        assert_eq!(t.history.len(), 0);
        t.add_transaction(txn);
        assert_eq!(t.history.len(), 1);
        assert!(t.is_valid());
    }

    #[test]
    fn lots_of_history() {
        // Same token
        let uid = U256::from(123);

        // 3 accounts
        let (a1, skey1) = gen_addr_and_skey_pair(&[1; 32]);
        let (a2, skey2) = gen_addr_and_skey_pair(&[2; 32]);
        let (a3, skey3) = gen_addr_and_skey_pair(&[3; 32]);

        // Construct history...
        // txn1: a3 -> a1
        let txn1 = Transaction::new(a1, uid, U256::from(0)).sign(&skey3);
        // txn2: a1 -> a2
        let txn2 = Transaction::new(a2, uid, U256::from(1)).sign(&skey1);
        // txn3: a2 -> a3
        let txn3 = Transaction::new(a3, uid, U256::from(2)).sign(&skey2);

        let txns = vec![txn1, txn2, txn3];
        assert!(is_history_valid(&txns));
    }
}

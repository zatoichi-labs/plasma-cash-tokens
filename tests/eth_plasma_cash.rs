#![feature(unsize)]
extern crate plasma_cash_token;
use plasma_cash_token::*;

extern crate rand;

extern crate secp256k1;
use secp256k1::{Secp256k1, Message, RecoverableSignature, key};

extern crate keccak_hash;
use keccak_hash::keccak;

extern crate ethereum_types;
use ethereum_types::{Address};

type U256 = [u8; 32];
type H256 = [u8; 32];

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
        Message::from_slice(&self.leaf_hash()).unwrap()
    }

    pub fn sign(&self, skey: &key::SecretKey) -> Transaction {
        assert!(self.signature.is_none());
        let ctx = Secp256k1::new();
        let sig = ctx.sign_recoverable(&self.unsigned_message(), skey).unwrap();
        Transaction::new_signed(self.newOwner, self.tokenId, self.prevBlkNum, sig)
    }

    pub fn receiver(&self) -> Option<Address> {
        Some(self.newOwner)
    }

    pub fn sender(&self) -> Option<Address> {
        let ctx = Secp256k1::new();
        let msg_hash = self.unsigned_message();
        let pkey = ctx.recover(&msg_hash, &self.signature.unwrap()).unwrap();
        Some(pkey_to_address(&pkey))
    }
}

impl PlasmaCashTxn<U256, H256> for Transaction {

    fn token_id(&self) -> U256 {
        self.tokenId
    }

    fn valid(&self) -> bool {
        // Signature is there, and it's valid
        self.sender().is_some()
    }

    fn empty_leaf_hash() -> H256 {
        Self::hash_fn()(&[0; 32])
    }

    fn hash_fn() -> (fn(&[u8]) -> H256) {
        (|b| *keccak(b).as_fixed_bytes() ) // TODO Figure out why this isn't working
    }

    fn leaf_hash(&self) -> H256 {
        // Construct vector of Tokens
        let new_owner = ethabi::Token::Address(self.newOwner);
        let token_id = ethabi::Token::Uint(ethereum_types::U256::from(self.tokenId));
        let prev_blk_num = ethabi::Token::Uint(ethereum_types::U256::from(self.prevBlkNum));
        let msg_vec = &[new_owner, token_id, prev_blk_num];
        // Encode vector of Tokens
        let msg_bytes = ethabi::encode(msg_vec);
        // Return keccak hash of encoded struct
        Self::hash_fn()(&msg_bytes)
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
            // Note: due to how Plasma Cash is designed, one of these is
            //       most likely not in the txn trie, unless the operator
            //       made malicious modifications.
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

/****************************** TESTS ***********************************/

fn gen_addr_and_skey_pair(data: &[u8]) -> (Address, key::SecretKey) {
    let ctx = Secp256k1::new();
    let skey = key::SecretKey::from_slice(&ctx, data).unwrap();
    let pkey = key::PublicKey::from_secret_key(&ctx, &skey).unwrap();
    let a = pkey_to_address(&pkey);
    (a, skey)
}

#[test]
fn validate_empty_token() {
    let uid = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,123];
    let t: Token<Transaction, U256, H256> = Token::new(uid);
    assert_eq!(t.uid, uid);
    assert_eq!(t.status, TokenStatus::RootChain);
    assert_eq!(t.history.len(), 0);
    assert!(t.is_valid());
}

#[test]
fn add_transaction() {
    let (a, skey) = gen_addr_and_skey_pair(&[1; 32]);
    let uid = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,123];
    let prev_blk_num = [0; 32];
    let mut t: Token<Transaction, U256, H256> = Token::new(uid);
    let txn = Transaction::new(a, uid, prev_blk_num).sign(&skey);

    assert_eq!(t.history.len(), 0);
    t.add_transaction(txn);
    assert_eq!(t.history.len(), 1);
    assert!(t.is_valid());
}

#[test]
fn lots_of_history() {
    // Same token
    let uid = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,123];

    // 3 accounts
    let (a1, skey1) = gen_addr_and_skey_pair(&[1; 32]);
    let (a2, skey2) = gen_addr_and_skey_pair(&[2; 32]);
    let (a3, skey3) = gen_addr_and_skey_pair(&[3; 32]);

    // Construct history...
    // txn1: a3 -> a1
    let prev_blk_num = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
    let txn1 = Transaction::new(a1, uid, prev_blk_num).sign(&skey3);
    // txn2: a1 -> a2
    let prev_blk_num = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1];
    let txn2 = Transaction::new(a2, uid, prev_blk_num).sign(&skey1);
    // txn3: a2 -> a3
    let prev_blk_num = [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,2];
    let txn3 = Transaction::new(a3, uid, prev_blk_num).sign(&skey2);

    let txns = vec![txn1, txn2, txn3];
    assert!(is_history_valid(&txns));
}
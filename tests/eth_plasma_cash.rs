extern crate plasma_cash_token;
use plasma_cash_token::{
    Token, TokenStatus,
    PlasmaCashTxn, TxnCmp,
    BigEndian, BitVec,
};

extern crate secp256k1;
use secp256k1::{Secp256k1, Message, RecoverableSignature, key};

extern crate keccak_hash;
use keccak_hash::keccak;

extern crate ethereum_types;
use ethereum_types::{Address, U256, H256};

extern crate ethabi;

fn pkey_to_address(pkey: &key::PublicKey) -> Address {
    let ctx = Secp256k1::new();
    let pkey_hash = keccak(pkey.serialize_vec(&ctx, false));
    Address::from_slice(&pkey_hash[..20])
}

// camelCase is used here because of EIP-712
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub struct UnsignedTransaction {
    pub newOwner: Address,
    pub tokenId: U256,
    pub prevBlkNum: U256,
}

impl UnsignedTransaction {
    pub fn encoded_msg(&self) -> Vec<u8> {
        // Construct vector of Tokens
        let new_owner = ethabi::Token::Address(self.newOwner);
        let token_id = ethabi::Token::Uint(self.tokenId);
        let prev_blk_num = ethabi::Token::Uint(self.prevBlkNum);
        let msg_vec = &[new_owner, token_id, prev_blk_num];
        // Encode vector of Tokens
        let msg_bytes = ethabi::encode(msg_vec);
        msg_bytes
    }

    fn unsigned_msg(&self) -> Message {
        let msg_bytes = self.encoded_msg();
        let msg_hash = keccak(msg_bytes);
        Message::from_slice(msg_hash.as_ref()).unwrap()
    }

    pub fn sign(&self, skey: &key::SecretKey) -> Transaction {
        let ctx = Secp256k1::new();
        let sig = ctx.sign_recoverable(&self.unsigned_msg(), skey).unwrap();
        Transaction::new_signed(*self, sig)
    }
}

#[allow(non_snake_case)]
pub struct Transaction {
    pub newOwner: Address,
    pub tokenId: U256,
    pub prevBlkNum: U256,
    signature: RecoverableSignature,
}

impl Transaction {
    // camelCase is used here because of EIP-712
    #[allow(non_snake_case)]
    pub fn new(newOwner: Address,
               tokenId: U256,
               prevBlkNum: U256) -> UnsignedTransaction
    {
        UnsignedTransaction {
            newOwner,
            tokenId,
            prevBlkNum,
        }
    }

    // camelCase is used here because of EIP-712
    #[allow(non_snake_case)]
    pub fn new_signed(txn: UnsignedTransaction,
               signature: RecoverableSignature) -> Transaction
    {
        Transaction {
            newOwner: txn.newOwner,
            tokenId: txn.tokenId,
            prevBlkNum: txn.prevBlkNum,
            signature,
        }
    }

    pub fn encoded_msg(&self) -> Vec<u8> {
        let unsigned_txn = UnsignedTransaction {
            newOwner: self.newOwner,
            tokenId: self.tokenId,
            prevBlkNum: self.prevBlkNum,
        };
        unsigned_txn.encoded_msg()
    }

    pub fn unsigned_msg(&self) -> Message {
        Message::from_slice(self.leaf_hash().as_ref()).unwrap()
    }

    pub fn receiver(&self) -> Option<Address> {
        Some(self.newOwner)
    }

    pub fn sender(&self) -> Option<Address> {
        let ctx = Secp256k1::new();
        let msg_hash = self.unsigned_msg();
        let pkey = ctx.recover(&msg_hash, &self.signature).unwrap();
        Some(pkey_to_address(&pkey))
    }
}

// This utility function is necessary to convert and meet
// the PlasmaCashTrait::token_id() signature
// TODO Can we get rid of this?
fn uid_to_bitvec(uid: U256) -> BitVec {
    let mut uid_bytes: [u8; 32] = [0; 32];
    uid.to_big_endian(&mut uid_bytes);
    BitVec::<BigEndian, u8>::from_slice(&uid_bytes)
}

impl PlasmaCashTxn<H256> for Transaction {

    fn token_id(&self) -> BitVec {
        uid_to_bitvec(self.tokenId)
    }

    fn valid(&self) -> bool {
        // Signature is there, and it's valid
        self.sender().is_some()
    }

    fn empty_leaf_hash() -> H256 {
        Self::hash_fn()(H256::from([0; 32]).as_ref())
    }

    fn hash_fn() -> (fn(&[u8]) -> H256) {
        |b| { keccak(b) }
    }

    fn leaf_hash(&self) -> H256 {
        // Return keccak hash of encoded struct
        Self::hash_fn()(&self.encoded_msg())
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
    let uid = U256::from(123);
    let t: Token<Transaction, H256> = Token::new(uid_to_bitvec(uid));
    assert_eq!(t.uid, uid_to_bitvec(uid));
    assert_eq!(t.status, TokenStatus::RootChain);
    assert_eq!(t.history.len(), 0);
    assert!(t.is_valid());
}

#[test]
fn add_transaction() {
    let (a, skey) = gen_addr_and_skey_pair(&[1; 32]);
    let uid = U256::from(123);
    let prev_blk_num = U256::from(0);
    let mut t: Token<Transaction, H256> = Token::new(uid_to_bitvec(uid));
    let txn = Transaction::new(a, uid, prev_blk_num).sign(&skey);

    assert_eq!(t.history.len(), 0);
    t.add_transaction(txn);
    assert_eq!(t.history.len(), 1);
    assert!(t.is_valid());
}

#[test]
fn lots_of_history() {
    // Same token
    let uid = U256::from(123);
    let mut t: Token<Transaction, H256> = Token::new(uid_to_bitvec(uid));

    // 3 accounts
    let (a1, skey1) = gen_addr_and_skey_pair(&[1; 32]);
    let (a2, skey2) = gen_addr_and_skey_pair(&[2; 32]);
    let (a3, skey3) = gen_addr_and_skey_pair(&[3; 32]);

    // Construct history...
    // txn1: a3 -> a1
    let prev_blk_num = U256::from(0);
    let txn1 = Transaction::new(a1, uid, prev_blk_num).sign(&skey3);
    t.add_transaction(txn1);

    // txn2: a1 -> a2
    let prev_blk_num = U256::from(1);
    let txn2 = Transaction::new(a2, uid, prev_blk_num).sign(&skey1);
    t.add_transaction(txn2);

    // txn3: a2 -> a3
    let prev_blk_num = U256::from(2);
    let txn3 = Transaction::new(a3, uid, prev_blk_num).sign(&skey2);
    t.add_transaction(txn3);

    // Verify txn history is valid
    assert!(t.is_valid());
}

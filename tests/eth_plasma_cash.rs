extern crate plasma_cash_tokens;
use plasma_cash_tokens::{
    Token, TokenStatus,
    PlasmaCashTxn, TxnCmp,
    BigEndian, BitVec,
};

extern crate secp256k1;
use secp256k1::{PublicKey, SecretKey, Message, Signature, RecoveryId, sign, recover};

extern crate keccak_hash;
use keccak_hash::keccak;

extern crate ethereum_types;
use ethereum_types::{Address, U256, H256};

extern crate ethabi;

fn pkey_to_address(pkey: &PublicKey) -> Address {
    let pkey_hash = keccak(&pkey.serialize().to_vec());
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
        Message::parse_slice(msg_hash.as_ref()).unwrap()
    }

    pub fn sign(&self, skey: &SecretKey) -> Transaction {
        let (sig, recovery_id) = sign(&self.unsigned_msg(), skey);
        Transaction::new_signed(*self, sig, recovery_id)
    }
}

#[allow(non_snake_case)]
pub struct Transaction {
    pub newOwner: Address,
    pub tokenId: U256,
    pub prevBlkNum: U256,
    signature: Signature,
    recovery_id: RecoveryId,
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
                      signature: Signature,
                      recovery_id: RecoveryId) -> Transaction
    {
        Transaction {
            newOwner: txn.newOwner,
            tokenId: txn.tokenId,
            prevBlkNum: txn.prevBlkNum,
            signature,
            recovery_id,
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
        Message::parse_slice(self.leaf_hash().as_ref()).unwrap()
    }

    pub fn receiver(&self) -> Option<Address> {
        Some(self.newOwner)
    }

    pub fn sender(&self) -> Option<Address> {
        let pkey = recover(&self.unsigned_msg(),
                           &self.signature,
                           &self.recovery_id).unwrap();
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

impl PlasmaCashTxn for Transaction {
    type HashType = H256;

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

fn gen_addr_and_skey_pair(data: &[u8]) -> (Address, SecretKey) {
    let skey = SecretKey::parse_slice(data).unwrap();
    let pkey = PublicKey::from_secret_key(&skey);
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
    assert!(t.add_transaction(txn).is_ok());
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
    assert!(t.add_transaction(txn1).is_ok());

    // txn2: a1 -> a2
    let prev_blk_num = U256::from(1);
    let txn2 = Transaction::new(a2, uid, prev_blk_num).sign(&skey1);
    assert!(t.add_transaction(txn2).is_ok());

    // txn3: a2 -> a3
    let prev_blk_num = U256::from(2);
    let txn3 = Transaction::new(a3, uid, prev_blk_num).sign(&skey2);
    assert!(t.add_transaction(txn3).is_ok());

    // Verify txn history is valid
    assert!(t.is_valid());
}

extern crate rand;

extern crate ethereum_types;
pub use ethereum_types::{Address, U256};

extern crate secp256k1;
use secp256k1::{Secp256k1, Message, RecoverableSignature, key};

extern crate keccak_hash;
use keccak_hash::keccak;

extern crate ethabi;

fn pkey_to_address(pkey: &key::PublicKey, ctx: &Secp256k1) -> Address {
    let pkey_hash = keccak(pkey.serialize_vec(ctx, false));
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

    pub fn signer(&self, ctx: &Secp256k1) -> Address {
        let msg_hash = self.unsigned_message();
        let pkey = ctx.recover(&msg_hash, &self.signature.unwrap()).unwrap();
        pkey_to_address(&pkey, &ctx)
    }
}

pub fn is_history_valid(history: &[Transaction], ctx: &Secp256k1) -> bool {
    // If token has no history, return True
    if history.len() == 0 {
        return true;
    }

    // History is valid if each transaction was signed by the previous receipient
    let signers: Vec<Address> = history.iter()
                                .skip(1) // Don't care about signer of 1st txn
                                .map(|txn| txn.signer(ctx))
                                .collect();
    let receivers: Vec<Address> = history.iter()
                                  // Note: Due to skip(1) above, this iterator
                                  // will exhaust before the last entry is used
                                  .map(|txn| txn.newOwner)
                                  .collect();
    let valid_txn_history = signers.iter()
                            .zip(receivers.iter())
                            .all(|a| a.0 == a.1);

    // Check that each transaction uses the same token ID (matching the one we have)
    let uid = history.first().unwrap().tokenId;
    let all_same_token_uid = history.iter()
                             .map(|txn| txn.tokenId)
                             .all(|token_id| token_id == uid);

    // Check that each transition increases the value of prevBlkNum from the former
    //let blk_ref_increases = history.iter()
    //                        .map(|txn| txn.prevBlkNum) // Reference to Plasma block prior to txn
    //                        .is_sorted_by(|prior_txn_blk, txn_blk| prior_txn_blk < txn_blk);
    //                        FIXME: is_sorted_by is in nightly...
    let mut blk_ref_increases = true;
    let mut prior_txn_blk = history.first().unwrap().prevBlkNum;
    history.iter().skip(1).for_each(|txn| {
        blk_ref_increases &= prior_txn_blk < txn.prevBlkNum;
        prior_txn_blk = txn.prevBlkNum;
    });

    // return:
    valid_txn_history && all_same_token_uid && blk_ref_increases
}

#[derive(Debug, PartialEq)]
pub enum TokenStatus {
    RootChain,
    Deposit,
    PlasmaChain,
    Withdrawal,
}

pub struct Token {
    pub uid: U256,
    pub owner: Address,
    pub status: TokenStatus,
    pub history: Vec<Transaction>,
    ctx: Secp256k1,
}

impl Token {
    pub fn new(uid: U256, owner: Address) -> Token {
        Token {
            uid,
            owner,
            status: TokenStatus::RootChain,
            history: Vec::new(),
            ctx: Secp256k1::new(),
        }
    }
    
    pub fn is_valid(&self) -> bool {
        let current_owner = match self.history.len() {
            0 => self.owner, //token.ownerOf(self.uid),
            _ => self.history.last().unwrap().newOwner,
        };

        return is_history_valid(&self.history, &self.ctx)
               && current_owner == self.owner;
    }

    pub fn add_transaction(&mut self, txn: Transaction) {
        assert_eq!(txn.signer(&self.ctx), self.owner);
        self.owner = txn.newOwner;
        self.history.push(txn);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn gen_addr_and_skey_pair(data: &[u8]) -> (Address, key::SecretKey) {
        let ctx = Secp256k1::new();
        let skey = key::SecretKey::from_slice(&ctx, data).unwrap();
        let pkey = key::PublicKey::from_secret_key(&ctx, &skey).unwrap();
        let a = pkey_to_address(&pkey, &ctx);
        (a, skey)
    }

    #[test]
    fn create_a_token() {
        let uid = U256::from(123);
        let (a, _) = gen_addr_and_skey_pair(&[1; 32]);
        let t = Token::new(uid, a);
        assert_eq!(t.uid, uid);
        assert_eq!(t.owner, a);
        assert_eq!(t.status, TokenStatus::RootChain);
        assert_eq!(t.history.len(), 0);
    }

    #[test]
    fn validate_empty_token() {
        let uid = U256::from(123);
        let (a, _) = gen_addr_and_skey_pair(&[1; 32]);
        let t = Token::new(uid, a);
        assert!(t.is_valid());
    }

    #[test]
    fn add_transaction() {
        let (a, skey) = gen_addr_and_skey_pair(&[1; 32]);
        let uid = U256::from(123);
        let mut t = Token::new(uid, a);
        let txn = Transaction::new(a, uid, U256::from(0));
        let sig = t.ctx.sign_recoverable(&txn.unsigned_message(), &skey).unwrap();
        let txn = Transaction::new_signed(a, uid, U256::from(0), sig);
        assert_eq!(t.history.len(), 0);
        t.add_transaction(txn);
        assert_eq!(t.history.len(), 1);
        assert!(t.is_valid());
    }

    #[test]
    fn lots_of_history() {
        let ctx = Secp256k1::new();
        // Same token
        let uid = U256::from(123);
        // 3 accounts
        let (a1, skey1) = gen_addr_and_skey_pair(&[1; 32]);
        let (a2, skey2) = gen_addr_and_skey_pair(&[2; 32]);
        let (a3, skey3) = gen_addr_and_skey_pair(&[3; 32]);
        // a3 -> a1
        let txn1 = Transaction::new(a1, uid, U256::from(0));
        let sig = ctx.sign_recoverable(&txn1.unsigned_message(), &skey3).unwrap();
        let txn1 = Transaction::new_signed(a1, uid, U256::from(0), sig);
        // a1 -> a2
        let txn2 = Transaction::new(a2, uid, U256::from(1));
        let sig = ctx.sign_recoverable(&txn2.unsigned_message(), &skey1).unwrap();
        let txn2 = Transaction::new_signed(a2, uid, U256::from(1), sig);
        // a2 -> a3
        let txn3 = Transaction::new(a3, uid, U256::from(2));
        let sig = ctx.sign_recoverable(&txn3.unsigned_message(), &skey2).unwrap();
        let txn3 = Transaction::new_signed(a3, uid, U256::from(2), sig);
        // History should all be valid!
        let txns = vec![txn1, txn2, txn3];
        assert!(is_history_valid(&txns, &ctx));
    }
}

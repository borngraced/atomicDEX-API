use crate::mm2::rpc::MmRpcBuilder;
use bitcrypto::{sha256, ChecksumType};
use chain::hash::H256;
use common::mm_error::MmError;
use common::privkey::key_pair_from_seed;
use derive_more::Display;
use keys::{Address, AddressFormat};
use secp256k1::{Message as Msg, PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};
use secp256k1::{Message, Signature};
use std::str::FromStr;
extern crate hex;
use super::lp_protocol::MmRpcResponse;
use lazy_static::{__Deref, lazy_static};
use serde_json::{self as json, Value as Json};
extern crate base64;
use crate::mm2::rpc::MmArc;
use crate::mm2::MmCtxBuilder;
use serde::Serialize;

lazy_static! {
    static ref SECP_VERIFY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    static ref SECP_SIGN: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum SignMessageRequestError {
    #[display(fmt = "Unable to sign message please confirm your credentials")]
    Internal { message: String },
}
#[derive(Debug, Deserialize)]
pub struct SignMessageRequest {
    userpass: String,
    method: String,
    mmrpc: String,
    id: usize,
    params: Json,
}
#[derive(Debug, Deserialize)]
pub struct SignMessageRequestParams {
    coin: String,
    message: String,
}
#[derive(Debug, Deserialize)]
pub struct SignMessageResponse {
    signature: String,
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum VerifyMessageRequestError {
    #[display(fmt = "Unable to verify message please confirm your credentials")]
    Internal { message: String },
}
#[derive(Debug, Deserialize)]
pub struct VerifyMessageRequest {
    userpass: String,
    method: String,
    mmrpc: String,
    id: usize,
    params: Json,
}
#[derive(Debug, Deserialize)]
pub struct VerifyMessageRequestParams {
    coin: String,
    message: String,
    signature: String,
}
#[derive(Debug, Deserialize)]
pub struct VerifyMessageResponse {
    is_valid: bool,
    address: String,
    pubkey: String,
}

pub type SignMessageRpcResult<T> = Result<T, MmError<SignMessageRequestError>>;
pub type VerifyMessageRpcResult<T> = Result<T, MmError<VerifyMessageRequestError>>;


pub fn sign_message(ctx: &MmArc, req: Json) -> SignMessageRpcResult<SignMessageResponse> {
    let req: SignMessageRequest = json::from_value(req).expect("Invalid request body");
    // if req.userpass != ctx.conf["rpc_password"] {
    //     unimplemented!()
    // }
    let params: SignMessageRequestParams = json::from_value(req.params).expect("Invalid request body");
    let key_pair = ctx.secp256k1_key_pair();
    // if !key_pair.private().compressed {
    //     unimplemented!()
    // }
    let message = sha256(params.message.as_bytes());
    let message = Msg::from_slice(&message.as_slice()).expect("");
    let secret = &key_pair.private().secret;
    let secret = SecretKey::from_slice(&secret.as_slice()).expect("");
    let sig = SECP_SIGN.sign(&message, &secret);
    let sig = sig.serialize_compact();
    //println!("sig {:?}", &sig,);
    let sig64 = base64::encode(&sig);
    //println!("sig {:?}", sig64,);
    Ok(SignMessageResponse{signature: sig64 })
}

pub fn verify_message(ctx: &MmArc, req: Json) -> VerifyMessageRpcResult<VerifyMessageResponse> {
    let req: VerifyMessageRequest = json::from_value(req).expect("Invalid request body");
    // if req.userpass != ctx.conf["rpc_password"] {
    //     unimplemented!()
    // }
    let params: VerifyMessageRequestParams = json::from_value(req.params).expect("Invalid request body");
    let key_pair = ctx.secp256k1_key_pair();
    let message = sha256(&params.message.as_bytes());
    let message = Message::from_slice(&message.as_slice()).expect("unable to get message");
    let public = PublicKey::from_str(&key_pair.public().to_string()).expect("unable to get publickey");
    let signature_from_base64 = base64::decode(&params.signature).expect("Signature decoding failed");
    let signature = Signature::from_compact(&signature_from_base64).expect("Signature verification failed");
    let verify = SECP_VERIFY.verify(&message, &signature, &public);
    let address_hash = key_pair.public().address_hash();
    let address = Address {
        prefix: 60,
        t_addr_prefix: 0,
        hrp: None,
        hash: address_hash,
        checksum_type: ChecksumType::DSHA256,
        addr_format: AddressFormat::Standard,
    };
    match verify {
        Ok(_) => {
          Ok(VerifyMessageResponse{ is_valid: true, address: address.display_address().unwrap().to_string(), pubkey: key_pair.public().to_string() })
        },
        Err(err) => return MmError::err(err.to_owned().to_string()).unwrap()
    }
}

// #[test]
// fn signmessage_test() {
//     let payload = json!({
//       "userpass":"culture",
//       "method":"sign_message",
//       "mmrpc":"2.0",
//       "id": 0,
//       "params":{
//         "coin":"RICK",
//         "message":"test"
//       }
//     });
//     let keypair =
//         key_pair_from_seed("spice describe gravity federal blast come thank unfair canal monkey style afraid").unwrap();

//     let mut ctx = MmCtxBuilder::default();
//     let ctx = ctx.with_secp256k1_key_pair(keypair);
//     let ctx = ctx.into_mm_arc();
//     let sign = sign_message(&ctx, payload);
//     let output = json::to_value(&sign).expect("Couldn't serialize MmRpcResponse");
//     println!("{:?}", output);
// }
// #[test]
// fn verifymessage_test() {
//     let payload = json!({
//       "userpass":"culture",
//       "method":"verify_message",
//       "mmrpc":"2.0",
//       "id": 0,
//       "params":{
//         "coin":"RICK",
//         "message":"test",
//         "signature": "lRnwxsSH5k07nbBlv10k/ZWD1N6F6L089Aozy2RwZxgbN4rUE2TMxVlRV/xnxgxia+rluch5Gr52vOwodifBKQ=="
//       }
//     });
//     let keypair =
//         key_pair_from_seed("spice describe gravity federal blast come thank unfair canal monkey style afraid").unwrap();

//     let mut ctx = MmCtxBuilder::default();
//     let ctx = ctx.with_secp256k1_key_pair(keypair);
//     let ctx = ctx.into_mm_arc();
//     let verify = verify_message(&ctx, payload);
//     let output = json::to_value(&verify).expect("Couldn't serialize MmRpcResponse");
//     println!("{:?}", output);
// }

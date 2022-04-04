#[macro_use] use crate::Json;
use bitcrypto::{dhash256, sha256, ChecksumType};
use chain::hash::H256;
use common::mm_ctx::MmCtxBuilder;
use common::privkey::key_pair_from_seed;
use common::{mm_ctx::MmArc, mm_error::MmError, HttpStatusCode};
use derive_more::Display;
use http::StatusCode;
use keys::{Address, AddressFormat};
use secp256k1::{Message as Msg, Secp256k1, SecretKey, SignOnly, VerifyOnly};
use secp256k1::{PublicKey, Signature};
lazy_static! {
    static ref SECP_VERIFY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    static ref SECP_SIGN: Secp256k1<SignOnly> = Secp256k1::signing_only();
}
extern crate hex;

#[derive(Serialize, Display, SerializeErrorType, Debug)]
#[serde(tag = "error_type", content = "error_data")]
pub enum SignMessageRequestError {
    Internal(String),
}

// Start sign struct construction
#[derive(Debug, Deserialize, Clone)]
pub struct SignMessageRequest {
    pub userpass: String,
    pub mathod: String,
    pub mmrpc: String,
    pub id: usize,
    pub params: SignParams,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignMessageResponse {
    mmrpc: String,
    result: SignatureT,
    id: usize,
}
#[derive(Debug, Deserialize, Clone)]
struct SignatureT {
    signature: String,
}
// {
//   "mmrpc":"2.0",
//   "result":{
//     "signature":"HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4="
//   },
//   "id":0
// }
#[derive(Debug, Deserialize, Clone)]
pub struct SignResponse {
    mmrpc: String,
    result: SignResult,
    id: usize,
}
#[derive(Debug, Deserialize, Clone)]
pub struct SignParams {
    coin: String,
    message: String,
}
#[derive(Debug, Deserialize, Clone)]
pub struct SignResult {
    signature: String,
}
pub type SignMessageRpcResult<T> = Result<Json<T>, MmError<SignMessageRequestError>>;

impl HttpStatusCode for SignMessageRequestError {
    fn status_code(&self) -> StatusCode {
        match self {
            SignMessageRequestError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub fn sign_message(req: Json) -> SignMessageRpcResult<SignMessageResponse> {
    let method = req["method"].as_str().expect("Unable to find userpass").to_string();
    if method != "sign_message".to_string() {
        return MmError::err(SignMessageRequestError::Internal(
            "Unknown method, please check again.".to_string(),
        ));
    }
    let message = req["params"]["message"]
        .as_str()
        .expect("Please provide a message to sign")
        .to_string();
    let userpass = req["userpass"]
        .as_str()
        .expect("Please provide your userpass/keyphrase")
        .to_string();

    let keypair = &key_pair_from_seed(&userpass);
    let my_public_key = match keypair {
        Ok(key) => key.public().to_string(),
        Err(e) => return MmError::err(SignMessageRequestError::Internal(e.to_string())),
    };
    let _my_private_key = match keypair {
        Ok(key) => key.private().to_string(),
        Err(e) => return MmError::err(SignMessageRequestError::Internal(e.to_string())),
    };

    let address_hash = match keypair {
        Ok(key) => key.public().address_hash(),
        Err(e) => return MmError::err(SignMessageRequestError::Internal(e.to_string())),
    };

    let my_address = Address {
        prefix: 60,
        t_addr_prefix: 0,
        hash: address_hash,
        checksum_type: ChecksumType::DSHA256,
        hrp: None,
        addr_format: AddressFormat::Standard,
    };
    let message = sha256(&message.as_bytes());
    let secret_key = sha256(&my_public_key.as_bytes());

    let message = Msg::from_slice(message.as_slice()).unwrap();
    let secret_key = SecretKey::from_slice(secret_key.as_slice()).unwrap();
    let signature = SECP_SIGN.sign(&message, &secret_key);
    
    Ok(SignMessageResponse {
        mmrpc: "2.0".to_string(),
        result: SignatureT {
            signature: format!("{}", signature),
        },
        id: 0,
    })
}

#[derive(Serialize, Display, SerializeErrorType, Debug)]
#[serde(tag = "error_type", content = "error_data")]
pub enum VerifyMessageRequestError {
    Internal(String),
}

// Start sign struct construction
#[derive(Debug, Deserialize, Clone)]
pub struct VerifyMessageRequest {
    pub userpass: String,
    pub mathod: String,
    pub mmrpc: String,
    pub id: usize,
    pub params: VerifyMessageParams,
}
#[derive(Debug, Deserialize, Clone)]
pub struct VerifyMessageParams {
    coin: bool,
    message: String,
    signature: String,
}
#[derive(Debug, Deserialize, Clone)]
pub struct VerifyMessageResponse {
    is_valid: bool,
    address: String,
    pubkey: String,
}
// {
//   "mmrpc":"2.0",
//   "result":{
//     "signature":"HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4="
//   },
//   "id":0
// }
#[macro_use]
#[derive(Debug, Deserialize, Clone)]
pub struct VerifyResult {
    signature: String,
}
pub type VerifyMessageRpcResult<T> = Result<T, MmError<VerifyMessageRequestError>>;

impl HttpStatusCode for VerifyMessageRequestError {
    fn status_code(&self) -> StatusCode {
        match self {
            VerifyMessageRequestError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub fn verify_message(req: Json) -> VerifyMessageRpcResult<VerifyMessageResponse> {
    let method = req["method"].as_str().expect("Please provide a method").to_string();
    if method != "verify_message".to_string() {
        return MmError::err(VerifyMessageRequestError::Internal(
            "Unknown method, please check again.".to_string(),
        ));
    }
    let message = req["params"]["message"]
        .as_str()
        .expect("Please provide a message to sign")
        .to_string();
    let userpass = req["userpass"]
        .as_str()
        .expect("Please provide your userpass/keyphrase")
        .to_string();
    let sig = req["paranms"]["signature"]
        .as_str()
        .expect("Please provide your signature")
        .to_string();

    let keypair = &key_pair_from_seed(&userpass);
    let my_public_key = match keypair {
        Ok(key) => key.public().to_string(),
        Err(e) => return MmError::err(VerifyMessageRequestError::Internal(e.to_string())),
    };
    let _my_private_key = match keypair {
        Ok(key) => key.private().to_string(),
        Err(e) => return MmError::err(VerifyMessageRequestError::Internal(e.to_string())),
    };

    let address_hash = match keypair {
        Ok(key) => key.public().address_hash(),
        Err(e) => return MmError::err(VerifyMessageRequestError::Internal(e.to_string())),
    };

    let my_address = Address {
        prefix: 60,
        t_addr_prefix: 0,
        hash: address_hash,
        checksum_type: ChecksumType::DSHA256,
        hrp: None,
        addr_format: AddressFormat::Standard,
    };
    let message = sha256(&message.as_bytes());
    let secret_key = sha256(&my_public_key.as_bytes());
    let message = Msg::from_slice(message.as_slice()).unwrap();
    //let sig = hex::decode(signature).unwrap;
    let signature = Signature::from_der(&sig.as_bytes()).unwrap();
    let secret_key = SecretKey::from_slice(secret_key.as_slice()).unwrap();
    //let pk = PublicKey::from_secret_key(&secp256k1, &secret_key);
    //let verify = SECP_VERIFY.verify(&message, &signature, my_public_key);
    println!("{}", signature);
    // match SECP_SIGN.verify(&message, &secret_key, my_public_key) {
    //     Ok(res) => Ok(VerifyMessageResponse {
    //         is_valid: true,
    //         address: &my_address.display_address(),
    //         pubkey: &_my_private_key,
    //     }),
    //     Err(err) => {
    //         return MmError::err(VerifyMessageRequestError::Internal(
    //             "Unknown method, please check again.".to_string(),
    //         ))
    //     },
    // }
    todo!()
}
#[test]
fn signmessag() {
    //let req =
    //let ctx = MmCtxBuilder::default().into_mm_arc();
    let json = json!({
      "userpass":"spice describe gravity federal blast come thank unfair canal monkey style afraid",
      "method":"sign_message",
      "mmrpc":"2.0",
      "id": 0,
      "params":{
        "coin":"RICK",
        "message":"test"
      }
    });
    let sign = sign_message(json);
    println!("{:?}", sign);
}
#[test]
fn verifymessag() {
    //let req =
    //let ctx = MmCtxBuilder::default().into_mm_arc();
    let json = json!({
      "userpass":"spice describe gravity federal blast come thank unfair canal monkey style afraid",
      "method":"verify_message",
      "mmrpc":"2.0",
      "id": 0,
      "params":{
        "coin":"RICK",
        "message":"test",
        "signature": "3045022100902a8c065aefc33d4ebddde20d5c0300e82faf24955ae7fccb11bb8a3455dd8b02206a8efbbe3573184f98a0e66612dffe60bdb537ec8157a9f01aec15c66e1b4c20"
      }
    });
    let sign = verify_message(json);
    println!("{:?}", sign);
}

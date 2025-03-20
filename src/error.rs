use blst::BLST_ERROR;
use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unable to decode public key at {}", .pub_key_index)]
    PublicKeyDecodeError { pub_key_index: usize },

    #[error("Unable to verify signature, error: {}", .verification_error)]
    SignatureVerificationError { verification_error: String },

    #[error("Mismatch between length of bitvec {} and length of public keys vector {}", .bit_vec_length, .public_key_length)]
    MismatchBetweenBitVecAndPublicKeys {
        bit_vec_length: u64,
        public_key_length: u64,
    },

    #[error("Invalid nonce, expected {}, got {}", .expected, .got)]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Invalid min_keys_needed parameter {}", .min_keys_needed)]
    InvalidMinKeysNeeded { min_keys_needed: u64 },

    #[error("Unable to decode signature payload {}", .error)]
    SignaturePayloadDecodeError { error: serde_json::Error },

    #[error("Invalid signature passed")]
    InvalidSignature,

    #[error("Unable to decode signature {:?}", .decode_error)]
    SignatureDecodeError { decode_error: BLST_ERROR },

    #[error("Participating key index is out of bounds index: {} and bit_vec_length is {}", .bit_vec_length, .index)]
    IndexOutOfBounds { index: u64, bit_vec_length: u64 }, // Add any other custom errors you like here.
                                                          // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

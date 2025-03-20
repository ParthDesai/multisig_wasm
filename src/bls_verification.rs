use crate::ContractError;
use bit_vec::BitVec;
use blst::min_pk::AggregatePublicKey;
use blst::{
    min_pk::{PublicKey, Signature},
    BLST_ERROR,
};

pub const DOMAIN_SEPERATION_TAG: &[u8] = b"DST_BLS_381_COSMWASM";

/// Verifies a BLS signature (potentially an aggregate signature) against a message and public keys.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `min_key_participation` - Min number of keys which must participate in the signing process
/// * `public_keys` - Array of public keys
/// * `bitvec` - Bitmap indicating which private keys participated in signing (1 = used, 0 = not used)
/// * `aggregated_signature` - The aggregate signature to verify
///
/// # Returns
///
/// * `Ok(true)` if the signature is valid
/// * `Ok(false)` if the signature is invalid
/// * `Err(String)` if an error occurred during verification
pub fn verify_signature(
    message: &[u8],
    min_key_participation: u64,
    public_keys: &[PublicKey],
    bitvec: BitVec,
    aggregated_signature: &Signature,
) -> Result<bool, String> {
    // Validate inputs
    if public_keys.is_empty() {
        return Err("No public keys provided".to_string());
    }

    if bitvec.len() < public_keys.len() {
        return Err("Smaller bitvec supplied".to_string());
    }

    if bitvec.count_ones() < min_key_participation {
        return Err("Less participation than min needed".to_string());
    }

    // Create a vector to store the public keys that participated in signing
    let mut participating_keys = Vec::new();

    // Filter the public keys based on the bitmap
    for (i, pk) in public_keys.iter().enumerate() {
        if bitvec.get(i).expect("Already checked above") {
            participating_keys.push(pk);
        }
    }

    // Aggregating public keys
    let aggregated_public_key = AggregatePublicKey::aggregate(&participating_keys, true)
        .map_err(|e| format!("BLS Error: {:?}", e))?;

    match aggregated_signature.aggregate_verify(
        true,
        &[message],
        DOMAIN_SEPERATION_TAG,
        &[&aggregated_public_key.to_public_key()],
        true,
    ) {
        BLST_ERROR::BLST_SUCCESS => Ok(true),
        BLST_ERROR::BLST_VERIFY_FAIL => Ok(false),
        err => Err(format!("Verification error: {:?}", err)),
    }
}

/// Utility function to create a bitmap from a list of indices
pub fn create_bitmap(
    total_keys: usize,
    participating_indices: &[usize],
) -> Result<BitVec, ContractError> {
    let mut bitvec = BitVec::from_elem(total_keys, false);

    for participating_index in participating_indices {
        if *participating_index >= bitvec.len() {
            return Err(ContractError::IndexOutOfBounds {
                index: *participating_index as u64,
                bit_vec_length: bitvec.len() as u64,
            });
        }

        bitvec.set(*participating_index, true);
    }

    Ok(bitvec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::{AggregateSignature, SecretKey, Signature};
    use rand::prelude::*;
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    #[test]
    fn test_signature_verification() {
        let mut sks = vec![];
        for i in 0u8..100 {
            sks.push(SecretKey::key_gen(&[i; 32], &[]).unwrap());
        }

        let mut pks = vec![];
        for i in 0u8..100 {
            pks.push(sks[i as usize].sk_to_pk());
        }

        let message = b"test message to sign with bls I am making this longer than 32 bytes";

        let sk_index_not_participating = 5;

        let mut rng = OsRng::default();
        let mut unique_indice_set = BTreeSet::new();
        let mut random_participation: Vec<usize> = vec![];
        for _ in 0..55 {
            let mut generated_value = rng.gen_range(0..100);
            while unique_indice_set.contains(&generated_value)
                || generated_value == sk_index_not_participating
            {
                generated_value = rng.gen_range(0..100)
            }
            unique_indice_set.insert(generated_value);
            random_participation.push(generated_value);
        }

        let mut signatures = vec![];
        for random_index in &random_participation {
            let sk = &sks[*random_index];
            signatures.push(sk.sign(message, DOMAIN_SEPERATION_TAG, &[]));
        }
        let signature_ref: Vec<&Signature> = signatures.iter().map(|s| s).collect();

        // Aggregate signatures
        let agg_sig = AggregateSignature::aggregate(signature_ref.as_slice(), true).unwrap();

        let bitmap = create_bitmap(100, &random_participation).unwrap();

        let result = verify_signature(message, 2, &[], bitmap.clone(), &agg_sig.to_signature());
        assert!(!result.is_ok());
        assert_eq!(
            result.err().unwrap(),
            String::from("No public keys provided")
        );

        let mut extra_pks = pks.clone();
        extra_pks.push(PublicKey::default());
        let result = verify_signature(
            message,
            50,
            &extra_pks,
            bitmap.clone(),
            &agg_sig.to_signature(),
        );
        assert!(!result.is_ok());
        assert_eq!(
            result.err().unwrap(),
            String::from("Smaller bitvec supplied")
        );

        let result = verify_signature(message, 60, &pks, bitmap.clone(), &agg_sig.to_signature());
        assert!(!result.is_ok());
        assert_eq!(
            result.err().unwrap(),
            String::from("Less participation than min needed")
        );

        // Verify
        let result = verify_signature(message, 50, &pks, bitmap, &agg_sig.to_signature());
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test with wrong bitmap
        random_participation[0] = sk_index_not_participating;
        let wrong_bitmap = create_bitmap(100, &random_participation).unwrap(); // Indices 0 and 1 (sk1 and sk2)
        let result = verify_signature(message, 50, &pks, wrong_bitmap, &agg_sig.to_signature());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}

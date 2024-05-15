#![no_std]

use k256::{elliptic_curve::ops::Reduce, AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};

use powdr_riscv_runtime::print;

/// convert a u32 array (arith machine format) to big-endian u8 array
fn u32_to_u8_be(a: &[u32], b: &mut [u8]) {
    assert_eq!(a.len(), 8);
    assert_eq!(b.len(), 32);
    for (i, n) in a.iter().rev().enumerate() {
        let bytes = n.to_be_bytes();
        b[i * 4..i * 4 + 4].copy_from_slice(&bytes)
    }
}

#[no_mangle]
pub fn main() {
    let x = [
        0x16f81798u32,
        0x59f2815b,
        0x2dce28d9,
        0x029bfcdb,
        0xce870b07,
        0x55a06295,
        0xf9dcbbac,
        0x79be667e,
    ];
    let y = [
        0xfb10d4b8u32,
        0x9c47d08f,
        0xa6855419,
        0xfd17b448,
        0x0e1108a8,
        0x5da4fbfc,
        0x26a3c465,
        0x483ada77,
    ];

    let mut x1: [u8; 32] = Default::default();
    let mut y1: [u8; 32] = Default::default();

    u32_to_u8_be(&x, &mut x1);
    u32_to_u8_be(&y, &mut y1);

    let p1 = EncodedPoint::from_affine_coordinates(&x1.into(), &y1.into(), false);
    let affine = AffinePoint::try_from(p1).unwrap();
    let mut pp: ProjectivePoint = affine.into();

    let rand_nums = [
        Scalar::reduce(U256::from_be_slice(&[
            175, 239, 217, 39, 247, 190, 32, 158, 21, 148, 141, 38, 241, 226, 20, 93, 44, 153, 67,
            91, 41, 245, 151, 131, 229, 125, 122, 145, 123, 166, 44, 164,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            4, 209, 85, 90, 60, 219, 234, 249, 43, 33, 214, 133, 9, 225, 207, 8, 249, 105, 29, 250,
            204, 233, 157, 62, 253, 27, 70, 252, 173, 222, 44, 106,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            165, 241, 68, 50, 90, 197, 219, 235, 216, 208, 41, 44, 193, 114, 110, 160, 254, 118,
            246, 56, 156, 244, 43, 27, 192, 80, 191, 139, 97, 33, 35, 247,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            247, 201, 150, 182, 116, 253, 28, 86, 150, 238, 223, 126, 241, 229, 177, 74, 167, 64,
            195, 253, 237, 43, 62, 196, 192, 105, 91, 128, 87, 185, 101, 27,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            223, 45, 172, 191, 165, 93, 124, 90, 19, 186, 179, 0, 113, 0, 0, 153, 192, 221, 126,
            19, 113, 0, 166, 72, 21, 245, 141, 145, 218, 251, 49, 50,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            44, 14, 122, 180, 112, 55, 54, 65, 91, 113, 130, 189, 145, 148, 124, 240, 190, 98, 203,
            231, 39, 157, 199, 80, 196, 0, 123, 226, 155, 173, 241, 81,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            117, 181, 206, 129, 53, 241, 125, 176, 117, 26, 103, 184, 248, 235, 97, 251, 145, 98,
            78, 115, 116, 48, 17, 208, 79, 70, 143, 141, 225, 147, 145, 219,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            214, 194, 195, 45, 65, 91, 148, 237, 40, 192, 109, 45, 188, 154, 110, 48, 238, 92, 153,
            88, 113, 235, 235, 98, 175, 230, 46, 228, 67, 165, 132, 189,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            237, 32, 236, 226, 145, 8, 40, 36, 28, 115, 83, 167, 135, 63, 153, 161, 79, 134, 11, 5,
            47, 121, 102, 187, 136, 223, 45, 226, 175, 89, 88, 27,
        ])),
        Scalar::reduce(U256::from_be_slice(&[
            131, 243, 19, 178, 194, 19, 12, 23, 212, 105, 166, 140, 14, 224, 71, 143, 34, 33, 223,
            72, 83, 32, 93, 242, 58, 1, 255, 196, 47, 255, 1, 47,
        ])),
    ];

    for i in 0..100 {
        pp = pp * rand_nums[i % rand_nums.len()];
        // pp += pp;
        // pp = pp.double();
    }
    print!("ok!\n");
}

// ========================================================

// use k256::{
//     ecdsa::{
//         signature::{Signer, Verifier},
//         Signature, SigningKey, VerifyingKey,
//     },
//     elliptic_curve::generic_array::GenericArray,
//     // elliptic_curve::rand_core::OsRng,
// };

// use hex_literal::hex;

// use powdr_riscv_runtime::print;

// #[no_mangle]
// pub fn main() {
//     let private_key1: [u8; 32] =
//         hex!("021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d595");
//     let signing_key1 = SigningKey::from_bytes(&GenericArray::from_slice(&private_key1)).unwrap();

//     let private_key2: [u8; 32] =
//         hex!("021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d594");
//     let signing_key2 = SigningKey::from_bytes(&GenericArray::from_slice(&private_key2)).unwrap();

//     let message = b"lorem ipsum blablabla";
//     let signature: Signature = signing_key1.sign(message);

//     let verifying_key1 = VerifyingKey::from(&signing_key1);
//     assert!(verifying_key1.verify(message, &signature).is_ok());
//     let verifying_key2 = VerifyingKey::from(&signing_key2);
//     assert!(verifying_key2.verify(message, &signature).is_err());
//     print!("ok!\n");
// }

// =====================================================================

// use hex_literal::hex;
// use k256::sha2::{Digest, Sha256};
// use k256::{
//     ecdsa::{signature::Verifier, RecoveryId, Signature, VerifyingKey},
//     EncodedPoint,
// };

// /// Signature recovery test vectors
// struct RecoveryTestVector {
//     pk: [u8; 33],
//     msg: &'static [u8],
//     sig: [u8; 64],
//     recid: RecoveryId,
// }

// const RECOVERY_TEST_VECTORS: &[RecoveryTestVector] = &[
//     // Recovery ID 0
//     RecoveryTestVector {
//         pk: hex!("021a7a569e91dbf60581509c7fc946d1003b60c7dee85299538db6353538d59574"),
//         msg: b"example message",
//         sig: hex!(
//             "ce53abb3721bafc561408ce8ff99c909f7f0b18a2f788649d6470162ab1aa032
//                      3971edc523a6d6453f3fb6128d318d9db1a5ff3386feb1047d9816e780039d52"
//         ),
//         recid: RecoveryId::new(false, false),
//     },
//     // Recovery ID 1
//     /*
//     RecoveryTestVector {
//     pk: hex!("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"),
//     msg: b"example message",
//     sig: hex!(
//     "46c05b6368a44b8810d79859441d819b8e7cdc8bfd371e35c53196f4bcacdb51
//     35c7facce2a97b95eacba8a586d87b7958aaf8368ab29cee481f76e871dbd9cb"
//     ),
//     recid: RecoveryId::new(true, false),
//     },
//     */
// ];

// pub fn verify_test_verify() -> bool {
//     for vector in RECOVERY_TEST_VECTORS {
//         let pk = VerifyingKey::from_sec1_bytes(&vector.pk).expect("Failed to decode public key");
//         let signature = Signature::from_slice(&vector.sig).unwrap();
//         if pk.verify(vector.msg, &signature).is_err() {
//             return false;
//         }
//     }

//     return true;
// }
// pub fn verify_test_recover() -> bool {
//     for vector in RECOVERY_TEST_VECTORS {
//         let digest = Sha256::new_with_prefix(vector.msg);
//         let sig = Signature::try_from(vector.sig.as_slice()).unwrap();
//         let recid = vector.recid;
//         let pk = VerifyingKey::recover_from_digest(digest, &sig, recid).unwrap();
//         if &vector.pk[..] != EncodedPoint::from(&pk).as_bytes() {
//             return false;
//         }
//     }

//     return true;
// }

// #[no_mangle]
// pub fn main() {
//     if !verify_test_verify() {
//         panic!("Oh noes");
//     }
// }

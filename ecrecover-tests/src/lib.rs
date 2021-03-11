
use ethcore_builtin::{EcRecover, Identity, Sha256, Implementation};
use hex_literal::hex;
use std::str::FromStr;
use parity_bytes::{BytesRef, ToPretty};
use tiny_keccak::{Hasher, Sha3};
use rustc_hex::FromHex;
use ethereum_types::H256;
use std::cmp::min;
use ethkey::{Signature, recover};

/// Ethereum builtins:
enum EthereumBuiltin {
	/// The identity function
	Identity(Identity),
	/// ec recovery
	EcRecover(EcRecover),
	/// sha256
	Sha256(Sha256)
}

impl FromStr for EthereumBuiltin {
	type Err = String;

	fn from_str(name: &str) -> Result<EthereumBuiltin, Self::Err> {
		match name {
			"identity" => Ok(EthereumBuiltin::Identity(Identity)),
			"ecrecover" => Ok(EthereumBuiltin::EcRecover(EcRecover)),
			"sha256" => Ok(EthereumBuiltin::Sha256(Sha256)),
			_ => return Err(format!("invalid builtin name: {}", name)),
		}
	}
}

impl Implementation for EthereumBuiltin {
	fn execute(&self, input: &[u8], output: &mut BytesRef) -> Result<(), &'static str> {
		match self {
			EthereumBuiltin::Identity(inner) => inner.execute(input, output),
			EthereumBuiltin::EcRecover(inner) => inner.execute(input, output),
			EthereumBuiltin::Sha256(inner) => inner.execute(input, output)
		}
	}
}

#[test]
fn test_uncompressed_ecrecover(){
	let i = hex!(
	"
	c5d6c454e4d7a8e8a654f5ef96e8efe41d21a65b171b298925414aa3dc061e37
	0000000000000000000000000000000000000000000000000000000000000000
	4011de30c04302a2352400df3d1459d6d8799580dceb259f45db1d99243a8d0c
	64f548b7776cb93e37579b830fc3efce41e12e0958cda9f8c5fcad682c610795"
	);

	let len = min(i.len(), 128);
	let mut input = [0; 128];
	input[..len].copy_from_slice(&i[..len]);

	let hash = H256::from_slice(&input[0..32]);
	//let v = H256::from_slice(&input[32..64]);
	let r = H256::from_slice(&input[64..96]);
	let s = H256::from_slice(&input[96..128]);

	let s = Signature::from_rsv(&r, &s, 0);
	assert_eq!(s.is_valid(), true);

	let public_key = recover(&s, &hash).unwrap(); // Uncompressed public key 64 bytes instead of 65

	let expected = "48250ebe88d77e0a12bcf530fe6a2cf1ac176945638d309b840d631940c93b78c2bd6d16f227a8877e3f1604cd75b9c5a8ab0cac95174a8a0a0f8ea9e4c10bca"; // Omitted 0x04
	assert_eq!(public_key.to_hex(), expected);
}

#[test]
fn test_sha3fib() {
	let mut sha3 = Sha3::v256();
	let i = ("0448250ebe88d77e0a12bcf530fe6a2cf1ac176945638d309b840d631940c93b78c2bd6d16f227a8877e3f1604cd75b9c5a8ab0cac95174a8a0a0f8ea9e4c10bca").from_hex().unwrap();
	sha3.update(&*i);
	let mut res: [u8; 32] = [0; 32];
	sha3.finalize(&mut res);
	dbg!(res.to_hex());
	let expected = "c7647f7e251bf1bd70863c8693e93a4e77dd0c9a689073e987d51254317dc704";
	assert_eq!(res.to_hex(), expected);
}

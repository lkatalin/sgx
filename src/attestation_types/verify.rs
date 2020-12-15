use super::{sample_quote::SAMPLE_QUOTE, key::Key, quote::{Quote, QuoteError}, sig::Signature};

//use byteorder::{ByteOrder, NativeEndian, ReadBytesExt};
//use dcap_ql::quote::{Qe3CertDataPckCertChain, Quote3SignatureEcdsaP256};
use openssl::{
    rand::rand_bytes,
    sha::sha256,
    symm::{decrypt_aead, encrypt_aead, Cipher},
    x509::*,
};
//use serde_json::{from_reader, to_writer, Deserializer};
use std::{
    borrow::Borrow,
    convert::TryFrom,
    env,
    error::Error,
    fs,
    io::{Cursor, Write},
    net::TcpStream,
};

const DAEMON_CONN: &'static str = "localhost:1034";
const ENCL_CONN: &'static str = "localhost:1066";

/// The tenant requests attestation of an enclave from the platform's attestation daemon, and
/// receives a Quote from the daemon. The Quote verifies the enclave's measurement. The tenant
/// verifies:
/// 1. That the Quote's PCK Certificate (embedded in the Cert Data) is valid.
/// 2. That the PCK Certificate's Key signed the platform's Attestation Key.
/// 3. That the Attestation Key signed the Quote.
/// 4. That the hashed material (containing the Attestation Key) signed by the PCK is valid.
///
/// For more information on Intel's PCK and certificate chains, you may refer to:
/// https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_PCK_Certificate_CRL_Spec-1.0.pdf
///
/// For more informtation on Intel's Attestation Key and the Quote, you may refer to:
/// https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

fn verify() -> Result<u32, QuoteError> {
    let quote_bytes = SAMPLE_QUOTE;

    // The tenant's PCK certificate chain must be loaded to verify the Quote's PCK Leaf
    // Certificate. The root certificate in this chain is trusted, since it is provided by the
    // tenant.
    //    let cert_chain_file = env::args()
    //        .nth(1)
    //        .expect("You must supply the path of a valid PCK certificate chain as the first argument.");
    //    let cert_chain_file_contents =
    //        fs::read_to_string(&cert_chain_file[..]).expect("PCK cert chain file path invalid.");
    //
    //    // These arguments are supplied by the tenant. They are the data that will be transmitted to the enclave.
    //    let val1 = env::args()
    //        .nth(2)
    //        .expect("You must supply two integers.")
    //        .parse::<u32>()?;
    //    let val2 = env::args()
    //        .nth(3)
    //        .expect("You must supply two integers.")
    //        .parse::<u32>()?;

    //    // The tenant requests attestation from the platform's attestation daemon.
    //    let mut daemon_conn = TcpStream::connect(DAEMON_CONN)?;
    //    to_writer(&mut daemon_conn, &b"Request attestation"[..])?;
    //
    //    // The tenant receives a Quote from the platform's attestation
    //    // daemon. This Quote verifies the enclave's self-measurement from its Report.
    //    let quote: Vec<u8> = from_reader(&mut daemon_conn)?;
    //    println!("CLIENT < SERVER: Quote (Attestation)");

    // The signed material for the Quoting Enclave's Attestation Key (Quote Header ||
    // ISV Enclave Report) is retrieved.
    let att_key_signed_material = Quote::raw_header_and_body(&quote_bytes)?;

    // The hashed material (containing the Attestation Key) signed by the PCK is retrieved.
    let hashed_reportdata = Quote::raw_pck_hash(&quote_bytes)?;

    // This parses the Quote's signature section.
    let quote = Quote::try_from(quote_bytes)?;
    // TODO: difference between Body vs Report? Should this be a Report?
    let enclave_report = quote.get_body();
    let q_sig = quote.get_sigdata();
    let q_enclave_report_sig = q_sig.get_report_sig();
    let q_qe_report = q_sig.get_qe_report();
    let q_qe_report_sig = q_sig.get_qe_report_sig();
    let q_att_key_pub = q_sig.get_attkey();
    let q_auth_data = q_sig.get_qe_auth();
    let q_cert_type = q_sig.get_qe_cert_data_type();
    println!("Cert data type: {:?}", q_cert_type);
    assert_eq!(0, 1);

    // The Quote's Certification Data contains the PCK Cert Chain and PCK Certificate;
    // the embedded PCK signs the Attestation Key.
    let cert_data = q_sig.get_qe_cert_data();
    // TODO: Make sure this is a leaf cert


    //    // The PCK chain is reconstructed with the Quote's leaf cert added to end of tenant's chain.
    //    let cert_chain = cert_chain::CertChain::new_from_chain(
    //        X509::stack_from_pem(cert_chain_file_contents.as_bytes())?,
    //        &quote_pck_leaf_cert,
    //    );
    //    cert_chain.len_ok()?;
    //
    //    // The PCK certificate chain's issuers and signatures are verified.
    //    cert_chain.verify_issuers()?;
    //    cert_chain.verify_sigs()?;
    //    println!("CLIENT: 	 PCK cert chain OK");

    // The Attestation Key's signature on the Quote is verified.
//    let attestation_key = Key::new_from_xy(&q_att_key_pub)?;
//    let quote_signature = Signature::try_from(q_enclave_report_sig)?.to_der_vec()?;
//    attestation_key.verify_sig(&att_key_signed_material, &quote_signature)?;
//    println!("CLIENT: 	 Quote signature OK");
//
//    // The PCK's signature on the Attestation Public Key is verified.
//    let pc_key = Key::new_from_pubkey(quote_pck_leaf_cert.public_key()?);
//    let qe_report_signature = Signature::try_from(q_qe_report_sig)?.to_der_vec()?;
//    pc_key
//        .borrow()
//        .verify_sig(&q_qe_report, &qe_report_signature)?;
//    println!("CLIENT: 	 Attestation Key signature OK");
//
//    // This verifies that the hashed material signed by the PCK is correct.
//    let mut unhashed_data = Vec::new();
//    unhashed_data.extend(q_att_key_pub.to_vec());
//    unhashed_data.extend(q_auth_data.to_vec());
//    pc_key
//        .borrow()
//        .verify_hash(hashed_reportdata, unhashed_data)?;
//    println!("CLIENT: 	 Enclave report hash OK");
//
//    println!("\nCLIENT: 	 Attestation Complete");

    Ok(5)
}

#[test]
fn verifying() {
    let x = verify().unwrap();
    assert_eq!(6, x);
}

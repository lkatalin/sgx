// SPDX-License-Identifier: Apache-2.0

//! Verifies a V3 SGX Quote

mod cert_chain;
mod key;
mod sample_v3quote;
mod sig;

use key::Key;
use sample_v3quote::SAMPLE_V3QUOTE;
use sig::Signature;

use super::quote::{Quote, QuoteError};

use openssl::{
    rand::rand_bytes,
    sha::sha256,
    symm::{decrypt_aead, encrypt_aead, Cipher},
    x509::*,
};

use std::{
    borrow::Borrow,
    convert::TryFrom,
    env,
    error::Error,
    fs,
    io::{Cursor, Write},
    net::TcpStream,
    ops::Deref,
};

use percent_encoding::percent_decode;
use reqwest::blocking::get;

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

fn verify() -> Result<(), Box<dyn Error>> {
    let quote_bytes = &SAMPLE_V3QUOTE[..];

    // The material (Quote Header || ISV Enclave Report) signed by Quoting Enclave's Attestation Key
    // is retrieved.
    let att_key_signed_material = Quote::raw_header_and_body(quote_bytes)?;

    // The hashed material (containing the Attestation Key) signed by the PCK is retrieved.
    let hashed_reportdata = Quote::raw_pck_hash(quote_bytes)?;

    // Create the Quote struct and retrieve the Quote Report Body.
    let quote = Quote::try_from(quote_bytes)?;
    let enclave_report = quote.body();

    // Parse the Quote's signature section.
    let q_sig = quote.sigdata();
    let q_enclave_report_sig = q_sig.get_report_sig();
    let q_att_key_pub = q_sig.get_attkey();
    let q_qe_report = q_sig.get_qe_report().to_vec();
    let q_qe_report_sig = q_sig.get_qe_report_sig();
    let q_auth_data = q_sig.get_qe_auth();
    let q_cert_type = q_sig.get_qe_cert_data_type();

    // Use Intel's API to retrieve the publicly available PCK Certificate Chain, including the root
    // certificate and intermediate certificate. The embedded leaf certificate retrieved from the
    // Quote will be validated by this chain.
    let res = get("https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=processor")
        .expect("unable to get PCK cert data from Intel's API");
    let chain = res
        .headers()
        .get("SGX-PCK-CRL-Issuer-Chain")
        .unwrap()
        .as_bytes();
    let trusted_public_pck_chain = percent_decode(&chain).decode_utf8_lossy();

    // The Quote's Certification Data contains the PCK Cert Chain and PCK Leaf Certificate;
    // the PCK corresponding to the Leaf Certificate signs the Attestation Key.
    let certs = q_sig.get_qe_cert_data_as_pckchain()?;
    let quote_pck_leaf_cert = certs.leaf_cert();

    // The PCK chain is reconstructed with the Quote's leaf cert added to end of tenant's chain.
    let cert_chain = cert_chain::CertChain::new_from_chain(
        X509::stack_from_pem(trusted_public_pck_chain.deref().as_bytes())?,
        &quote_pck_leaf_cert,
    );
    cert_chain.len_ok()?;

    // The PCK certificate chain's issuers and signatures are verified.
    cert_chain.verify_issuers()?;
    cert_chain.verify_sigs()?;
    println!("CLIENT: 	 PCK cert chain OK");

    // The Attestation Key's signature on the Quote is verified.
    let attestation_key = Key::new_from_xy(&q_att_key_pub.to_vec())?;
    let quote_signature = Signature::try_from(&q_enclave_report_sig.to_vec()[..])?.to_der_vec()?;
    attestation_key.verify_sig(&att_key_signed_material, &quote_signature)?;
    println!("CLIENT: 	 Quote signature OK");

    // The PCK's signature on the Attestation Public Key is verified.
    let pc_key = Key::new_from_pubkey(quote_pck_leaf_cert.public_key()?);
    let qe_report_signature = Signature::try_from(&q_qe_report_sig.to_vec()[..])?.to_der_vec()?;
    pc_key
        .borrow()
        .verify_sig(&q_qe_report, &qe_report_signature)?;
    println!("CLIENT: 	 Attestation Key signature OK");

    // This verifies that the hashed material signed by the PCK is correct.
    let mut unhashed_data = Vec::new();
    unhashed_data.extend(q_att_key_pub.to_vec());
    unhashed_data.extend(q_auth_data.to_vec());
    pc_key
        .borrow()
        .verify_hash(hashed_reportdata, unhashed_data)?;
    println!("CLIENT: 	 Enclave report hash OK");
    println!("\nCLIENT: 	 Attestation Complete");

    Ok(())
}

#[test]
fn verify_sample_v3quote() {
    assert!(!verify().is_err());
}

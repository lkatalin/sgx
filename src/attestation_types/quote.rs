// SPDX-License-Identifier: Apache-2.0

//! The Quote structure is used to provide proof to an off-platform entity that an application
//! enclave is running with Intel SGX protections on a trusted Intel SGX enabled platform.
//! See Section A.4 in the following link for all types in this module:
//! https://download.01.org/intel-sgx/dcap-1.0/docs/SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.0.pdf

use std::{convert::TryFrom, fmt, vec::Vec};

use super::report::Body;

const QUOTE_HEADER_LEN: usize = 48;
const QUOTE_SIGNATURE_START_BYTE: usize = 436;
const ISV_ENCLAVE_REPORT_SIG_LEN: usize = 64;
const ATT_KEY_PUB_LEN: usize = 64;
const REPORT_DATA_OFFSET: usize = 320;
const PCK_HASH_LEN: usize = 32;
const _ECDSA_P256_SIGNATURE_LEN: usize = 64;
const _ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
const _QE3_VENDOR_ID_LEN: usize = 16;
const _QE3_USER_DATA_LEN: usize = 20;
const REPORT_BODY_LEN: usize = 384;
const _CPUSVN_LEN: usize = 16;
const _QUOTE_VERSION_3: u16 = 3;

/// The Quote version for DCAP is 3. Must be 2 bytes.
pub const VERSION: u16 = 3;

/// The length of an ECDSA signature is 64 bytes. This value must be 4 bytes.
pub const ECDSASIGLEN: u32 = 64;

/// Intel's Vendor ID, as specified in A.4, Table 3. Must be 16 bytes.
pub const INTELVID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

#[derive(Debug, Clone)]
/// Error type for Quote module
pub struct QuoteError(String);

impl fmt::Display for QuoteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl std::error::Error for QuoteError {
    fn description(&self) -> &str {
        &self.0
    }
}

/// Section A.4, Table 9
#[repr(u16)]
pub enum CertDataType {
    /// Byte array that contains concatenation of PPID, CPUSVN,
    /// PCESVN (LE), PCEID (LE)
    PpidPlaintext = 1,

    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-2048-OAEP, CPUSVN,  PCESVN (LE), PCEID (LE)
    PpidRSA2048OAEP = 2,

    /// Byte array that contains concatenation of PPID encrypted
    /// using RSA-3072-OAEP, CPUSVN, PCESVN (LE), PCEID (LE)
    PpidRSA3072OAEP = 3,

    /// PCK Leaf Certificate
    PCKLeafCert = 4,

    /// Concatenated PCK Cert Chain  (PEM formatted).
    /// PCK Leaf Cert||Intermediate CA Cert||Root CA Cert
    PCKCertChain = 5,

    /// Intel SGX Quote (not supported).
    Quote = 6,

    /// Platform Manifest (not supported).
    Manifest = 7,
}

impl Default for CertDataType {
    fn default() -> Self {
        Self::PCKCertChain
    }
}

/// ECDSA  signature, the r component followed by the
/// s component, 2 x 32 bytes.
/// A.4, Table 6
#[derive(Default)]
#[repr(C)]
pub struct ECDSAP256Sig {
    /// r component
    pub r: [u8; 32],

    /// s component
    pub s: [u8; 32],
}

/// EC KT-I Public Key, the x-coordinate followed by
/// the y-coordinate (on the RFC 6090P-256 curve),
/// 2 x 32 bytes.
/// A.4, Table 7
#[derive(Default)]
#[repr(C)]
pub struct ECDSAPubKey {
    /// x coordinate
    pub x: [u8; 32],

    /// y coordinate
    pub y: [u8; 32],
}

/// A.4, Table 4
#[derive(Default)]
#[repr(C)]
pub struct SigData {
    isv_enclave_report_sig: ECDSAP256Sig,
    ecdsa_attestation_key: ECDSAPubKey,
    qe_report: Body,
    qe_report_sig: ECDSAP256Sig,
    qe_auth: Vec<u8>,
    qe_cert_data_type: CertDataType,
    qe_cert_data: Vec<u8>,
}

/// The type of Attestation Key used to sign the Report.
#[repr(u16)]
#[derive(Eq, PartialEq)]
pub enum AttestationKeyType {
    /// ECDSA-256-with-P-256 curve
    ECDSA256P256 = 2,

    /// ECDSA-384-with-P-384 curve; not supported
    ECDSA384P384 = 3,
}

impl Default for AttestationKeyType {
    fn default() -> Self {
        AttestationKeyType::ECDSA256P256
    }
}

impl AttestationKeyType {
    fn from_u16(value: u16) -> AttestationKeyType {
        match value {
            2 => AttestationKeyType::ECDSA256P256,
            3 => AttestationKeyType::ECDSA384P384,
            _ => panic!("Unknown value: {}", value),
        }
    }
}

/// Unlike the other parts of the Quote, this structure
/// is transparent to the user.
/// Section A.4, Table 3
#[repr(C)]
pub struct QuoteHeader {
    /// Version of Quote structure, 3 in the ECDSA case.
    pub version: u16,

    /// Type of attestation key used. Only one type is currently supported:
    /// 2 (ECDSA-256-with-P-256-curve).
    pub att_key_type: AttestationKeyType,

    /// Reserved.
    reserved: u32,

    /// Security version of the QE.
    pub qe_svn: u16,

    /// Security version of the Provisioning Cerfitication Enclave.
    pub pce_svn: u16,

    /// ID of the QE vendor.
    pub qe_vendor_id: [u8; 16],

    /// Custom user-defined data. For the Intel DCAP library, the first 16 bytes
    /// contain a QE identifier used to link a PCK Cert to an Enc(PPID). This
    /// identifier is consistent for every quote generated with this QE on this
    /// platform.
    pub user_data: [u8; 20],
}

impl Default for QuoteHeader {
    fn default() -> Self {
        Self {
            version: VERSION,
            att_key_type: Default::default(),
            reserved: Default::default(),
            qe_svn: Default::default(),
            pce_svn: Default::default(),
            qe_vendor_id: INTELVID,
            user_data: [0u8; 20],
        }
    }
}

impl TryFrom<&[u8; 48]> for QuoteHeader {
    type Error = QuoteError;
    
    fn try_from(bytes: &[u8; 48]) -> Result<Self, Self::Error> {

        let mut tmp = [0u8; 2];

        tmp.copy_from_slice(&bytes[0..2]);
        let version = u16::from_le_bytes(tmp);
        if version != VERSION {
            return Err(QuoteError(format!("Incorrect Quote version, expected: {}, actual: {}; cannot convert bytes to QuoteHeader", VERSION, version)));
        }

        tmp.copy_from_slice(&bytes[2..4]);
        let att_key_type = AttestationKeyType::from_u16(u16::from_le_bytes(tmp));
        if att_key_type != AttestationKeyType::default() {
            return Err(QuoteError(format!("Incorrect Quote key type, expected: {}, actual: {}; cannot convert bytes to QuoteHeader", AttestationKeyType::default() as u16, att_key_type as u16)));
        }

        tmp.copy_from_slice(&bytes[8..10]);
        let qe_svn = u16::from_le_bytes(tmp);

        tmp.copy_from_slice(&bytes[10..12]);
        let pce_svn = u16::from_le_bytes(tmp);

        let mut qe_vendor_id = [0u8; 16];
        qe_vendor_id.copy_from_slice(&bytes[12..28]);

        let mut user_data = [0u8; 20];
        user_data.copy_from_slice(&bytes[28..48]);

        Ok(Self {
            version,
            att_key_type,
            reserved: Default::default(),
            qe_svn,
            pce_svn,
            qe_vendor_id,
            user_data,
        })
    }
}

/// Section A.4
/// All integer fields are in little endian.
#[repr(C, align(4))]
pub struct Quote {
    /// Header for Quote structure; transparent to the user.
    pub header: QuoteHeader,

    /// Report of the atteste enclave.
    isv_enclave_report: Body,

    /// Size of the Signature Data field.
    sig_data_len: u32,

    /// Variable-length data containing the signature and
    /// supporting data.
    sig_data: SigData,
}

impl Default for Quote {
    fn default() -> Self {
        Self {
            header: Default::default(),
            isv_enclave_report: Default::default(),
            sig_data_len: ECDSASIGLEN,
            sig_data: Default::default(),
        }
    }
}

impl Quote {
    /// This vector of the Quote Header and ISV Enclave Report is the material signed
    /// by the Quoting Enclave's Attestation Key and should be returned in raw form to
    /// verify the Attestation Key's signature. Specifically, the header's version
    /// number should also be kept intact in the vector, rather than being abstracted
    /// into the Header enum.
    pub fn raw_header_and_body(quote: &[u8]) -> Result<Vec<u8>, QuoteError> {
        Ok(quote[0..(QUOTE_HEADER_LEN + REPORT_BODY_LEN)].to_vec())
    }

    /// The Report Data of the QE Report holds a SHA256 hash of (ECDSA Attestation Key || QE
    /// Authentication data) || 32-0x00's. This hash must be verified for attestation.
    /// The Report comes after the ISV Enclave Report Signature and Attestation Public Key in the
    /// Quote Signature. The structure of the QE Report in the Quote Signature is identical
    /// to the structure of any enclave's Report, so the Report Data begins at byte 320 of the Report.
    pub fn raw_pck_hash(quote: &[u8]) -> Result<&[u8], QuoteError> {
        let start_byte = QUOTE_SIGNATURE_START_BYTE
            + ISV_ENCLAVE_REPORT_SIG_LEN
            + ATT_KEY_PUB_LEN
            + REPORT_DATA_OFFSET;
        Ok(&quote[start_byte.. start_byte + PCK_HASH_LEN])
    }

    /// Retrieves Quote Header
    pub fn get_header(self) -> QuoteHeader {
        self.header
    }

    /// Retrieves Quote Body
    pub fn get_body(self) -> Body {
        self.isv_enclave_report
    }

    /// Retrieves Quote's sig length
    pub fn get_siglen(self) -> u32 {
        self.sig_data_len
    }

    /// Retrieves Quote's signature data
    pub fn get_sigdata(self) -> SigData {
        self.sig_data
    }
}

#[cfg(test)]
testaso! {
    struct QuoteHeader: 4, 48 => {
        version: 0,
        att_key_type: 2,
        reserved: 4,
        qe_svn: 8,
        pce_svn: 10,
        qe_vendor_id: 12,
        user_data: 28
    }
}

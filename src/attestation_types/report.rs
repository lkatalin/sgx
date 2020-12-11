// SPDX-License-Identifier: Apache-2.0

//! Section 38.15
//! The REPORT structure is the output of the EREPORT instruction, and must be 512-Byte aligned.

use crate::types::{attr::{Attributes, Flags, Xfrm}, isv, misc::MiscSelect};

use core::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
/// Error type for Report module
pub struct ReportError;

/// This struct is separated out from the Report to be usable by the Quote struct.
/// Table 38-21
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C)]
pub struct Body {
    /// The security version number of the processor
    pub cpusvn: [u8; 16],

    /// Bit vector specifying which extended features are saved to the
    /// MISC region of the SSA frame when an AEX occurs
    pub miscselect: MiscSelect,

    /// Reserved
    reserved0: [u32; 7],

    /// Attributes of the enclave (Section 38.7.1)
    pub attributes: Attributes,

    /// Value of SECS.MRENCLAVE
    pub mrenclave: [u8; 32],

    /// Reserved
    reserved1: [u32; 8],

    /// Value from SECS.MRSIGNER
    pub mrsigner: [u8; 32],

    /// Reserved
    reserved2: [u32; 24],

    /// Product ID of the enclave
    pub isvprodid: isv::ProdId,

    /// Security version number of the enclave
    pub isvsvn: isv::Svn,

    /// Reserved
    reserved3: [u32; 15],

    /// Data provided by the user and protected by the Report's MAC (Section 38.15.1)
    pub reportdata: [u16; 32],
}

impl TryFrom<&[u8; 384]> for Body {
    type Error = ReportError;

    fn try_from(bytes: &[u8; 384]) -> Result<Self, Self::Error> {
        
        let mut cpusvn = [0u8; 16];
        cpusvn.copy_from_slice(&bytes[0..16]);

        let mut misc = [0u8; 4];
        misc.copy_from_slice(&bytes[16..20]);
        let miscselect = MiscSelect::from_bits(u32::from_le_bytes(misc)).unwrap();

        let mut f = [0u8; 8];
        let mut x = [0u8; 8];
        f.copy_from_slice(&bytes[48..56]);
        x.copy_from_slice(&bytes[56..64]);
        let f = u64::from_le_bytes(f);
        let x = u64::from_le_bytes(x);
        let attributes = Attributes::new(
            Flags::from_bits(f).unwrap(),
            Xfrm::from_bits(x).unwrap(),
        );

        let mut mrenclave = [0u8; 32];
        mrenclave.copy_from_slice(&bytes[64..96]);

        let mut mrsigner = [0u8; 32];
        mrsigner.copy_from_slice(&bytes[128..160]);

        let mut prodid = [0u8; 2];
        prodid.copy_from_slice(&bytes[256..258]);
        let isvprodid = isv::ProdId::new(u16::from_le_bytes(prodid));

        let mut svn = [0u8; 2];
        svn.copy_from_slice(&bytes[258..260]);
        let isvsvn = isv::Svn::new(u16::from_le_bytes(svn));

        let mut reportdata = [0u16; 32];
        let (_, rd, _) = unsafe { bytes[320..384].align_to::<u16>() };
        reportdata.copy_from_slice(rd);

        Ok(Self {
            cpusvn,
            miscselect,
            reserved0: Default::default(),
            attributes,
            mrenclave,
            reserved1: Default::default(),
            mrsigner,
            reserved2: Default::default(),
            isvprodid,
            isvsvn,
            reserved3: Default::default(),
            reportdata
        })
    }
}

/// Table 38-21
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(C, align(512))]
pub struct Report {
    /// The body of the Report
    pub reportbody: Body,

    /// Value for key wear-out protection
    pub keyid: [u8; 32],

    /// MAC on the report using the Report Key
    pub mac: u128,

    /// Padding to 512 bytes
    padding: [u128; 5],
}

#[cfg(test)]
testaso! {
    struct Body: 4, 384 => {
        cpusvn: 0,
        miscselect: 16,
        reserved0: 20,
        attributes: 48,
        mrenclave: 64,
        reserved1: 96,
        mrsigner: 128,
        reserved2: 160,
        isvprodid: 256,
        isvsvn: 258,
        reserved3: 260,
        reportdata: 320
    }

    struct Report: 512, 512 => {
        reportbody: 0,
        keyid: 384,
        mac: 416,
        padding: 432
    }
}

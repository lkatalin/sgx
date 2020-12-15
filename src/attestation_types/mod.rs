// SPDX-License-Identifier: Apache-2.0

//! Intel SGX Documentation is available at the following link.
//! Section references in further documentation refer to this document.
//! https://www.intel.com/content/dam/www/public/emea/xe/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf

#[cfg(feature = "crypto")]
/// Certificate chain module
pub mod cert_chain;

#[cfg(feature = "crypto")]
/// Key module
pub mod key;

#[cfg(feature = "crypto")]
/// A sample quote
pub mod sample_quote;

#[cfg(feature = "crypto")]
/// Signature module
pub mod sig;

#[cfg(feature = "crypto")]
/// Module to verify a Quote
pub mod verify;

#[cfg(feature = "std")]
/// Quote module
pub mod quote;

/// Report module
pub mod report;

/// TargetInfo module
pub mod ti;

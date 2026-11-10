// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
//
// SPDX-License-Identifier: (RPL-1.5 OR AGPL-3.0-only) AND Apache-2.0
//
// You may instead use this file under the GNU Affero General Public License, version 3 only
// (LICENSE-AGPL-3.0). The notice below is for the RPL.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

use std::io;

use thiserror::Error;

/// Result type returned by fallible `ewf_image` APIs.
pub type Result<T> = std::result::Result<T, EwfError>;

/// Error type used by EWF readers, writers, and probe helpers.
#[derive(Debug, Error)]
pub enum EwfError {
    /// An underlying operating-system or stream I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The input does not start with a recognized EWF file signature.
    #[error("invalid EWF signature")]
    InvalidSignature,

    /// A caller-provided buffer was too short for the requested operation.
    #[error("buffer too short: needed {needed} bytes, found {actual}")]
    BufferTooShort {
        /// Minimum number of bytes required.
        needed: usize,
        /// Number of bytes that were actually available.
        actual: usize,
    },

    /// No segment files were found or supplied.
    #[error("no EWF segments found for {0}")]
    NoSegments(String),

    /// A recognized encrypted EWF image was opened without a password.
    #[error("password required for encrypted EWF image")]
    PasswordRequired,

    /// An encrypted EWF password verifier rejected the supplied password.
    #[error("password rejected for encrypted EWF image")]
    PasswordRejected,

    /// Decrypted EWF data did not pass the format's structural validation.
    #[error("decrypted EWF data failed validation")]
    DecryptionValidationFailed,

    /// The image uses a valid EWF feature that this crate does not support.
    #[error("unsupported EWF feature: {0}")]
    Unsupported(String),

    /// The operation was cancelled after an abort signal.
    #[error("operation aborted")]
    Aborted,

    /// The image or supplied chunk data is structurally invalid.
    #[error("malformed EWF image: {0}")]
    Malformed(String),
}

// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Elijah Brigham
//
// This file is changed from ebrig/ewf-image (https://github.com/ebrig/ewf-image), whose code is
// under the Apache License 2.0 (LICENSE-APACHE).
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

/// On-disk section identifier, preserving unknown producer-defined types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum SectionKind {
    /// EWF1 ASCII section name.
    Ewf1(String),
    /// EWF2 numeric section identifier.
    Ewf2(u32),
}

/// A section's location in its original segment. Payloads are not retained.
/// These are the descriptors accepted during opening, not a fresh integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SectionInfo {
    /// Zero-based segment index, resolving through `Image::segment_filename`.
    pub segment_index: usize,
    /// Original section identifier.
    pub kind: SectionKind,
    /// Descriptor byte offset within the segment.
    pub descriptor_offset: u64,
    /// Payload byte offset within the segment.
    pub data_offset: u64,
    /// Payload byte length, excluding descriptor and padding.
    pub data_size: u64,
    /// EWF1 next descriptor or EWF2 previous descriptor offset.
    pub linked_descriptor_offset: u64,
    /// Raw EWF2 data flags; zero for EWF1.
    pub data_flags: u32,
}

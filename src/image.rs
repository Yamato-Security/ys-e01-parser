use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use lru::LruCache;
pub(crate) mod recovery;
use md5::Digest as _;

use crate::codepage::decode_header_bytes;
use crate::decode::{
    ChunkEncoding, decode_chunk_with_padding, raw_chunk_size_cap, validate_encoded_size,
    zlib_compressed_chunk_size_cap,
};
use crate::encryption::EncryptionContext;
use crate::format::{ewf1, ewf2};
use crate::index::{LazyChunkIndex, TableRange, TableRangeKind};
use crate::lenient::{Defect, DefectKind, Leniency};
use crate::metadata::{
    Ewf2Geometry, detect_ewf1_header_profile, detect_ewf1_header2_profile, parse_error2_data,
    parse_ewf2_case_data, parse_ewf2_device_info, parse_ewf2_device_info_values,
    parse_ewf2_error_table_data, parse_header_data, parse_header2_data, parse_session_data,
    parse_xhash_data, parse_xheader_data,
};
use crate::reader_cache::{TABLE_PAGE_SIZE, TablePageCache, TablePageKey};
use crate::reader_statistics::{ReaderCacheInfo, ReaderStatistics, ReaderStatisticsCollector};
use crate::segment::discover_segments;
use crate::signature::{check_segment_files_corruption, check_segment_files_encryption};
use crate::single_files::{parse_ewf1_single_files_data, parse_ewf2_single_files_data};
use crate::types::{
    AcquisitionError, ChunkCacheCapacity, CompressionLevel, CompressionMethod, CompressionValues,
    DataChunk, DataChunkEncoding, EncodedDataChunk, EwfMetadata, Format, FormatProfile,
    HeaderCodepage, HeaderDateFormat, ImageInfo, MediaFlags, MediaInfo, MediaType, MemoryExtent,
    OpenOptions, OpenStrictness, SectorRange, SegmentFileVersion, SingleFileEntry,
    SingleFilePermission, SingleFileSource, SingleFileSubject, SingleFilesAuxTables,
    SingleFilesInfo, StoredHashes,
};
use crate::{
    EncryptionInfo, EwfError, EwfPassword, Result, SectionInfo, SectionKind, SegmentSource,
};

const MAX_DECOMPRESSED_METADATA: u64 = 16 * 1024 * 1024;
const MAX_CHUNK_SIZE: u64 = 128 * 1024 * 1024;
const EWF1_HASH_SECTION_SIZE: u64 = 36;
const EWF1_DIGEST_SECTION_SIZE: u64 = 80;
const EWF1_LTREE_HEADER_SIZE: usize = 48;
const EWF1_LOGICAL_SPARSE_FLAG: u32 = 0x0400_0000;
const EWF2_HASH_SECTION_SIZE: u64 = 32;
const EWF2_TABLE_HEADER_V2_SIZE: u64 = 32;
const EWF2_TABLE_FOOTER_SIZE: u64 = 16;
const TABLE_CHECKSUM_BUFFER_SIZE: usize = 64 * 1024;

/// Reader type accepted by [`Image::open_readers`].
///
/// Implemented automatically for any `Read + Seek + Send` type. Override
/// [`SegmentReader::segment_len`] when obtaining the length by seeking to the
/// end is not appropriate.
pub trait SegmentReader: Read + Seek + Send {
    /// Returns the total length of this segment in bytes.
    fn segment_len(&mut self) -> io::Result<u64> {
        let position = self.stream_position()?;
        let len = self.seek(SeekFrom::End(0))?;
        self.seek(SeekFrom::Start(position))?;
        Ok(len)
    }
}

impl<T> SegmentReader for T where T: Read + Seek + Send {}

type SuppliedSegmentReader = Box<dyn SegmentReader>;

#[derive(Debug, Clone)]
/// Opened EWF image and logical media reader.
pub struct Image {
    inner: Arc<ImageInner>,
}

#[derive(Debug)]
struct ImageInner {
    info: ImageInfo,
    sections: Vec<SectionInfo>,
    open_strictness: OpenStrictness,
    encryption_info: Option<EncryptionInfo>,
    encryption_contexts: Vec<Option<EncryptionContext>>,
    segments: Mutex<SegmentFilePool>,
    segment_handle_available: Condvar,
    positioned_sources: Option<Vec<SegmentSource>>,
    index: LazyChunkIndex,
    chunk_cache: Mutex<LruCache<u64, Arc<Vec<u8>>>>,
    chunk_in_flight: Mutex<HashMap<u64, Arc<ChunkFlight>>>,
    chunk_cache_capacity_bytes: u64,
    table_page_cache: Mutex<TablePageCache>,
    statistics: Arc<ReaderStatisticsCollector>,
    checksum_errors: Mutex<Vec<SectorRange>>,
    // Read only through the `verify` feature's integrity findings.
    #[cfg_attr(not(feature = "verify"), allow(dead_code))]
    defects: Vec<Defect>,
    read_zero_chunk_on_error: AtomicBool,
    abort_signaled: AtomicBool,
}

struct SegmentFilePool {
    files: Vec<Option<SegmentFileHandle>>,
    lengths: Vec<Option<u64>>,
    ever_opened: Vec<bool>,
    open_order: VecDeque<usize>,
    maximum_open_handles: Option<usize>,
    mode: SegmentFilePoolMode,
    statistics: Arc<ReaderStatisticsCollector>,
}

enum SegmentFileHandle {
    Path(PathSegmentReader),
    Supplied(SuppliedSegmentReader),
}

struct PathSegmentReader {
    file: Arc<File>,
    position: u64,
}

struct PositionedSegmentLease<'a> {
    file: Option<Arc<File>>,
    segments: &'a Mutex<SegmentFilePool>,
    available: &'a Condvar,
}

#[derive(Debug)]
struct ChunkFlight {
    complete: Mutex<bool>,
    ready: Condvar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentFilePoolMode {
    ReopenFromPath,
    SuppliedReaders,
}

impl std::fmt::Debug for SegmentFilePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentFilePool")
            .field("segment_count", &self.files.len())
            .field(
                "known_length_count",
                &self
                    .lengths
                    .iter()
                    .filter(|length| length.is_some())
                    .count(),
            )
            .field(
                "ever_opened_count",
                &self.ever_opened.iter().filter(|opened| **opened).count(),
            )
            .field("open_count", &self.open_count())
            .field("open_order", &self.open_order)
            .field("maximum_open_handles", &self.maximum_open_handles)
            .field("mode", &self.mode)
            .field("statistics_enabled", &self.statistics.enabled())
            .finish()
    }
}

impl SegmentFileHandle {
    fn as_reader_mut(&mut self) -> &mut dyn SegmentReader {
        match self {
            Self::Path(reader) => reader,
            Self::Supplied(reader) => reader.as_mut(),
        }
    }

    fn path_file(&self) -> Option<&Arc<File>> {
        match self {
            Self::Path(reader) => Some(&reader.file),
            Self::Supplied(_) => None,
        }
    }

    fn idle_path_handle(&self) -> bool {
        self.path_file()
            .is_some_and(|file| Arc::strong_count(file) == 1)
    }
}

impl Read for PathSegmentReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = read_file_at(&self.file, buffer, self.position)?;
        self.position = self.position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for PathSegmentReader {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
            SeekFrom::End(offset) => self.file.metadata()?.len().checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "segment seek out of range"))?;
        self.position = position;
        Ok(position)
    }
}

impl Drop for PositionedSegmentLease<'_> {
    fn drop(&mut self) {
        // Release the active lease before waking a waiter. Otherwise the waiter
        // can observe this handle as busy and go back to sleep after the only
        // notification associated with the release.
        self.file.take();
        // Synchronize the predicate change with the mutex used by waiters. A
        // waiter cannot slip between checking the pool and going to sleep.
        let _segments = self
            .segments
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.available.notify_one();
    }
}

impl PositionedSegmentLease<'_> {
    fn file(&self) -> &File {
        self.file
            .as_deref()
            .expect("positioned segment lease retains its file until drop")
    }
}

#[derive(Debug, Clone, Copy)]
struct Chunk {
    segment_index: usize,
    offset: u64,
    encoded_size: u64,
    logical_size: usize,
    encoding: ChunkEncoding,
    validate_checksum: bool,
}

#[derive(Clone, Copy)]
struct Ewf1DecodedEntry {
    compressed: bool,
    offset: u64,
}

#[derive(Debug, Clone)]
/// Seekable cursor over an [`Image`] logical media stream.
pub struct ImageCursor {
    image: Image,
    position: u64,
}

#[derive(Debug, Clone)]
/// Seekable cursor over one logical single-file catalog entry.
pub struct SingleFileCursor {
    image: Image,
    entry: SingleFileEntry,
    position: u64,
}

impl Image {
    /// Opens an EWF image from the first segment path.
    ///
    /// Adjacent segments are discovered automatically from the first path.
    ///
    /// # Errors
    ///
    /// Returns an error if no segment set can be discovered, a segment cannot
    /// be read, or the image is unsupported or malformed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, OpenOptions::default())
    }

    /// Opens an EWF image from the first segment path with explicit options.
    ///
    /// # Errors
    ///
    /// Returns an error if no segment set can be discovered, a segment cannot
    /// be read, or the image is unsupported or malformed.
    pub fn open_with_options(path: impl AsRef<Path>, options: OpenOptions) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segment_paths(paths, options, None)
    }

    /// Opens an EWF image using caller-supplied password bytes.
    ///
    /// Supplying a password for an unencrypted image is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error if no segment set can be discovered, a segment cannot
    /// be read, the password is rejected, or the image is unsupported or
    /// malformed.
    pub fn open_with_password(path: impl AsRef<Path>, password: &EwfPassword) -> Result<Self> {
        Self::open_with_options_and_password(path, OpenOptions::default(), password)
    }

    /// Opens an EWF image using explicit options and caller-supplied password
    /// bytes.
    ///
    /// Supplying a password for an unencrypted image is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error if no segment set can be discovered, a segment cannot
    /// be read, the password is rejected, or the image is unsupported or
    /// malformed.
    pub fn open_with_options_and_password(
        path: impl AsRef<Path>,
        options: OpenOptions,
        password: &EwfPassword,
    ) -> Result<Self> {
        let paths = discover_segments(path.as_ref())?;
        Self::open_segment_paths(paths, options, Some(password))
    }

    /// Opens an EWF image from an explicit ordered segment path list.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a segment cannot be read, or the
    /// image is unsupported or malformed.
    pub fn open_segments<P, I>(paths: I) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        Self::open_segments_with_options(paths, OpenOptions::default())
    }

    /// Opens an EWF image from explicit ordered segment paths with options.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a segment cannot be read, or the
    /// image is unsupported or malformed.
    pub fn open_segments_with_options<P, I>(paths: I, options: OpenOptions) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let paths = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        Self::open_segment_paths(paths, options, None)
    }

    /// Opens an explicit ordered segment path list using explicit options and
    /// caller-supplied password bytes.
    ///
    /// Supplying a password for an unencrypted image is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a segment cannot be read, the
    /// password is rejected, or the image is unsupported or malformed.
    pub fn open_segments_with_options_and_password<P, I>(
        paths: I,
        options: OpenOptions,
        password: &EwfPassword,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let paths = paths
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        Self::open_segment_paths(paths, options, Some(password))
    }

    /// Opens an EWF image from supplied readers and segment labels.
    ///
    /// Supplied readers are kept by the image and are not reopened from the
    /// filesystem. Labels are used anywhere this crate reports segment paths.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a reader fails, or the image is
    /// unsupported or malformed.
    pub fn open_readers<N, R, I>(segments: I) -> Result<Self>
    where
        N: Into<PathBuf>,
        R: SegmentReader + 'static,
        I: IntoIterator<Item = (N, R)>,
    {
        Self::open_readers_with_options(segments, OpenOptions::default())
    }

    /// Opens an EWF image from supplied readers with explicit options.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a reader fails, or the image is
    /// unsupported or malformed.
    pub fn open_readers_with_options<N, R, I>(segments: I, options: OpenOptions) -> Result<Self>
    where
        N: Into<PathBuf>,
        R: SegmentReader + 'static,
        I: IntoIterator<Item = (N, R)>,
    {
        let mut paths = Vec::new();
        let mut readers = Vec::new();
        for (name, reader) in segments {
            paths.push(name.into());
            readers.push(Box::new(reader) as SuppliedSegmentReader);
        }
        Self::open_segment_readers(paths, readers, options, None)
    }

    /// Opens supplied readers using explicit options and caller-supplied
    /// password bytes.
    ///
    /// Supplying a password for an unencrypted image is harmless. Supplied
    /// readers are retained by the image and are never reopened by path.
    ///
    /// # Errors
    ///
    /// Returns an error if the list is empty, a reader fails, the password is
    /// rejected, or the image is unsupported or malformed.
    pub fn open_readers_with_options_and_password<N, R, I>(
        segments: I,
        options: OpenOptions,
        password: &EwfPassword,
    ) -> Result<Self>
    where
        N: Into<PathBuf>,
        R: SegmentReader + 'static,
        I: IntoIterator<Item = (N, R)>,
    {
        let mut paths = Vec::new();
        let mut readers = Vec::new();
        for (name, reader) in segments {
            paths.push(name.into());
            readers.push(Box::new(reader) as SuppliedSegmentReader);
        }
        Self::open_segment_readers(paths, readers, options, Some(password))
    }

    fn open_segment_paths(
        paths: Vec<PathBuf>,
        options: OpenOptions,
        password: Option<&EwfPassword>,
    ) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty segment list".into()));
        }

        crate::publication::ensure_no_pending(&paths[0])?;

        let statistics = Arc::new(ReaderStatisticsCollector::new(
            options.reader_statistics_enabled(),
        ));
        let segments =
            SegmentFilePool::new_path(paths.len(), options.maximum_open_handles(), statistics)?;
        Self::open_segment_sources(paths, segments, options, password, None, None)
    }

    // Only the acquisition checkpoint reader may open a sealed prefix whose
    // volume declares the eventual full size. Public opens keep exact coverage.
    pub(crate) fn open_acquisition_prefix(
        paths: Vec<PathBuf>,
        expected_size: u64,
        committed_size: u64,
    ) -> Result<Self> {
        let options = OpenOptions::default().with_chunk_cache_size(1);
        let statistics = Arc::new(ReaderStatisticsCollector::new(false));
        let segments =
            SegmentFilePool::new_path(paths.len(), options.maximum_open_handles(), statistics)?;
        Self::open_segment_sources(
            paths,
            segments,
            options,
            None,
            None,
            Some((expected_size, committed_size)),
        )
    }

    fn open_segment_readers(
        paths: Vec<PathBuf>,
        readers: Vec<SuppliedSegmentReader>,
        options: OpenOptions,
        password: Option<&EwfPassword>,
    ) -> Result<Self> {
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty segment list".into()));
        }
        if paths.len() != readers.len() {
            return Err(EwfError::Malformed(
                "segment reader count does not match segment labels".into(),
            ));
        }

        let statistics = Arc::new(ReaderStatisticsCollector::new(
            options.reader_statistics_enabled(),
        ));
        let segments =
            SegmentFilePool::new_readers(readers, options.maximum_open_handles(), statistics)?;
        Self::open_segment_sources(paths, segments, options, password, None, None)
    }

    /// Opens explicitly ordered, named positioned sources with default options.
    /// Supports EWF1 and EWF2. Names are labels, never reopened as filesystem paths.
    pub fn open_sources<N: Into<PathBuf>>(
        sources: impl IntoIterator<Item = (N, SegmentSource)>,
    ) -> Result<Self> {
        Self::open_sources_with_options(sources, OpenOptions::default())
    }

    /// Opens positioned sources with reader controls. All supplied backings stay
    /// owned for the image lifetime; an open-handle limit below their count is rejected.
    pub fn open_sources_with_options<N: Into<PathBuf>>(
        sources: impl IntoIterator<Item = (N, SegmentSource)>,
        options: OpenOptions,
    ) -> Result<Self> {
        Self::open_positioned_sources(sources, options, None)
    }

    /// Opens encrypted positioned sources using one caller-supplied password.
    pub fn open_sources_with_options_and_password<N: Into<PathBuf>>(
        sources: impl IntoIterator<Item = (N, SegmentSource)>,
        options: OpenOptions,
        password: &EwfPassword,
    ) -> Result<Self> {
        Self::open_positioned_sources(sources, options, Some(password))
    }

    fn open_positioned_sources<N: Into<PathBuf>>(
        sources: impl IntoIterator<Item = (N, SegmentSource)>,
        options: OpenOptions,
        password: Option<&EwfPassword>,
    ) -> Result<Self> {
        let (paths, sources): (Vec<_>, Vec<_>) = sources
            .into_iter()
            .map(|(name, source)| (name.into(), source))
            .unzip();
        if paths.is_empty() {
            return Err(EwfError::NoSegments("empty segment list".into()));
        }
        let statistics = Arc::new(ReaderStatisticsCollector::new(
            options.reader_statistics_enabled(),
        ));
        let readers = sources
            .iter()
            .map(|source| Box::new(source.cursor()) as SuppliedSegmentReader)
            .collect();
        let segments =
            SegmentFilePool::new_readers(readers, options.maximum_open_handles(), statistics)?;
        Self::open_segment_sources(paths, segments, options, password, Some(sources), None)
    }

    fn open_segment_sources(
        paths: Vec<PathBuf>,
        mut segments: SegmentFilePool,
        options: OpenOptions,
        password: Option<&EwfPassword>,
        positioned_sources: Option<Vec<SegmentSource>>,
        acquisition_prefix: Option<(u64, u64)>,
    ) -> Result<Self> {
        let statistics = Arc::clone(&segments.statistics);
        let mut ranges = Vec::new();
        let mut section_summaries = Vec::new();
        let mut metadata = EwfMetadata::default();
        let mut acquisition_errors = Vec::new();
        let mut memory_extents = Vec::new();
        let mut single_files = None;
        let mut ewf2_single_files_tables = SingleFilesAuxTables::default();
        let mut ewf2_increment_data = Vec::new();
        let mut ewf2_final_information = None;
        let mut ewf2_restart_data = None;
        let mut ewf2_analytical_data = None;
        let mut sessions = Vec::new();
        let mut tracks = Vec::new();
        let mut stored_hashes = StoredHashes::default();
        let mut media = MediaInfo::default();
        let mut chunk_size = 0;
        let mut logical_size = 0;
        let mut acquisition_complete = true;
        let mut format = None;
        let mut format_profile = None;
        let mut format_profile_hint_only = false;
        let mut next_ewf1_chunk = 0_u64;
        let mut discovered_table_chunks = 0_u64;
        let mut expected_set_identifier: Option<[u8; 16]> = None;
        let mut expected_ewf1_media = None;
        let mut expected_ewf1_compression_method = None;
        let mut expected_ewf2_header_profile = None;
        let mut expected_ewf2_device_information = None;
        let mut expected_ewf2_case_data = None;
        let mut encryption_info = None;
        let mut encryption_contexts = Vec::with_capacity(paths.len());
        let mut leniency = Leniency::new(options.strictness());

        for (segment_index, path) in paths.iter().enumerate() {
            statistics.record_segment_parse();
            let (parsed, encryption_context, observed_encryption_info) = {
                let file = segments.file_mut(segment_index, path)?;
                let encryption_metadata = ewf1::read_xways_encryption(file.as_reader_mut())?;
                let observed_encryption_info =
                    encryption_metadata.as_ref().map(EncryptionInfo::from_xways);
                let encryption_context = encryption_metadata
                    .as_ref()
                    .map(|metadata| {
                        let password = password.ok_or(EwfError::PasswordRequired)?;
                        EncryptionContext::derive(metadata, password)
                    })
                    .transpose()?;
                let parsed = parse_segment(
                    file.as_reader_mut(),
                    &paths[0],
                    segment_index,
                    Ewf1SegmentContext {
                        first_chunk: next_ewf1_chunk,
                        inherited_media_geometry: expected_ewf1_media,
                    },
                    &mut leniency,
                    options.header_codepage(),
                    &statistics,
                )?;
                (parsed, encryption_context, observed_encryption_info)
            };
            if segment_index == 0 {
                encryption_info = observed_encryption_info;
            } else if observed_encryption_info != encryption_info {
                return Err(EwfError::Malformed(
                    "X-Ways EWF1 encryption settings differ across segments".into(),
                ));
            }
            encryption_contexts.push(encryption_context);
            section_summaries.extend(parsed.sections);
            let expected_segment_number = u64::try_from(segment_index + 1)
                .map_err(|_| EwfError::Malformed("segment index overflow".into()))?;
            if parsed.segment_number != expected_segment_number {
                return Err(EwfError::Malformed(format!(
                    "segment {} declares segment number {}, expected {}",
                    segment_index + 1,
                    parsed.segment_number,
                    expected_segment_number
                )));
            }
            validate_set_identifier(&mut expected_set_identifier, parsed.set_identifier)?;
            if let Some(observed) = parsed.ewf1_compression_method {
                if expected_ewf1_compression_method.is_some_and(|expected| expected != observed) {
                    return Err(EwfError::Malformed(
                        "EWF1 compression method mismatch across segments".into(),
                    ));
                }
                expected_ewf1_compression_method.get_or_insert(observed);
            }
            if let Some(observed) = parsed.ewf1_media_geometry {
                if expected_ewf1_media
                    .as_ref()
                    .is_some_and(|expected| expected != &observed)
                {
                    return Err(EwfError::Malformed(
                        "EWF1 media geometry mismatch across segments".into(),
                    ));
                }
                expected_ewf1_media.get_or_insert(observed);
            }
            validate_ewf2_header_profile(
                &mut expected_ewf2_header_profile,
                parsed.ewf2_header_profile,
            )?;
            if let Some(device_information) = parsed.ewf2_device_information.as_deref() {
                remember_ewf2_metadata_payload(
                    &mut expected_ewf2_device_information,
                    device_information,
                    "device information",
                )?;
            }
            if let Some(case_data) = parsed.ewf2_case_data.as_deref() {
                remember_ewf2_metadata_payload(
                    &mut expected_ewf2_case_data,
                    case_data,
                    "case data",
                )?;
            }
            if segment_index == 0 {
                chunk_size = parsed.chunk_size;
                logical_size = parsed.logical_size;
                acquisition_complete = parsed.acquisition_complete;
                media = parsed.media;
                metadata = parsed.metadata;
                acquisition_errors = parsed.acquisition_errors;
                memory_extents = parsed.memory_extents;
                single_files = parsed.single_files;
                ewf2_single_files_tables = parsed.ewf2_single_files_tables;
                ewf2_increment_data = parsed.ewf2_increment_data;
                ewf2_final_information = parsed.ewf2_final_information;
                ewf2_restart_data = parsed.ewf2_restart_data;
                ewf2_analytical_data = parsed.ewf2_analytical_data;
                sessions = parsed.sessions;
                tracks = parsed.tracks;
                format = Some(parsed.format);
                format_profile = Some(parsed.format_profile);
                format_profile_hint_only = parsed.format_profile_hint_only;
            } else {
                merge_segment_format_profile(
                    &mut format_profile,
                    &mut format_profile_hint_only,
                    parsed.format_profile,
                    parsed.format_profile_hint_only,
                )?;
                merge_acquisition_errors(&mut acquisition_errors, parsed.acquisition_errors)?;
                memory_extents.extend(parsed.memory_extents);
                merge_single_files(&mut single_files, parsed.single_files)?;
                merge_single_files_aux_tables(
                    &mut ewf2_single_files_tables,
                    parsed.ewf2_single_files_tables,
                )?;
                ewf2_increment_data.extend(parsed.ewf2_increment_data);
                merge_optional_ewf2_raw_section(
                    &mut ewf2_final_information,
                    parsed.ewf2_final_information,
                    "final information",
                )?;
                merge_optional_ewf2_string_section(
                    &mut ewf2_restart_data,
                    parsed.ewf2_restart_data,
                    "restart data",
                )?;
                merge_optional_ewf2_string_section(
                    &mut ewf2_analytical_data,
                    parsed.ewf2_analytical_data,
                    "analytical data",
                )?;
                sessions.extend(parsed.sessions);
                tracks.extend(parsed.tracks);
                acquisition_complete = parsed.acquisition_complete;
            }
            merge_hashes(&mut stored_hashes, &parsed.stored_hashes)?;
            if parsed.format == Format::Ewf1 {
                next_ewf1_chunk = next_ewf1_chunk
                    .checked_add(parsed.table_chunk_count)
                    .ok_or_else(|| EwfError::Malformed("EWF1 chunk count overflow".into()))?;
            }
            for range in &parsed.ranges {
                discovered_table_chunks = discovered_table_chunks.max(
                    range
                        .first_chunk
                        .checked_add(range.chunk_count)
                        .ok_or_else(|| {
                            EwfError::Malformed("table range chunk count overflow".into())
                        })?,
                );
            }
            ranges.extend(parsed.ranges);
        }

        let format = format.ok_or_else(|| EwfError::Malformed("image has no segments".into()))?;
        if format == Format::Ewf1
            && matches!(
                format_profile,
                Some(
                    FormatProfile::LogicalEnCase5
                        | FormatProfile::LogicalEnCase6
                        | FormatProfile::LogicalEnCase7
                )
            )
            && let Some(catalog) = single_files.as_ref()
        {
            logical_size = catalog.data_size;
        }
        if format == Format::Ewf2
            && expected_ewf2_device_information.is_none()
            && expected_ewf2_case_data.is_none()
        {
            return Err(EwfError::Malformed(
                "missing EWF2 device information or case data section".into(),
            ));
        }

        if logical_size == 0 && chunk_size > 0 {
            logical_size = chunk_size
                .checked_mul(discovered_table_chunks)
                .ok_or_else(|| EwfError::Malformed("logical size overflow".into()))?;
        }
        if discovered_table_chunks > 0 {
            media.chunk_count = Some(discovered_table_chunks);
        }
        if let Some((expected_size, committed_size)) = acquisition_prefix {
            if format != Format::Ewf1
                || logical_size != expected_size
                || committed_size == 0
                || committed_size > expected_size
            {
                return Err(EwfError::Malformed(
                    "invalid acquisition prefix geometry".into(),
                ));
            }
            logical_size = committed_size;
        }

        let info = ImageInfo {
            format,
            format_profile: format_profile.unwrap_or_default(),
            segment_count: paths.len(),
            segment_paths: paths,
            chunk_size,
            logical_size,
            acquisition_complete,
            header_codepage: options.header_codepage(),
            header_values_date_format: options.header_values_date_format(),
            media,
            metadata,
            stored_hashes,
            acquisition_errors,
            memory_extents,
            single_files,
            ewf2_single_files_tables,
            ewf2_increment_data,
            ewf2_final_information,
            ewf2_restart_data,
            ewf2_analytical_data,
            sessions,
            tracks,
        };
        let index = LazyChunkIndex::new(ranges, info.logical_size, info.chunk_size)?;
        let chunk_size = usize::try_from(info.chunk_size)
            .map_err(|_| EwfError::Malformed("chunk size does not fit usize".into()))?;
        let cache_entries = match options.chunk_cache_capacity() {
            ChunkCacheCapacity::Chunks(entries) => entries.max(1),
            ChunkCacheCapacity::Bytes(bytes) => bytes.checked_div(chunk_size).unwrap_or(0).max(1),
        };
        let cache_size =
            NonZeroUsize::new(cache_entries).expect("chunk cache size is at least one");
        let chunk_cache_capacity_bytes = u64::try_from(cache_entries)
            .unwrap_or(u64::MAX)
            .saturating_mul(info.chunk_size);

        let image = Self {
            inner: Arc::new(ImageInner {
                info,
                sections: section_summaries,
                open_strictness: options.strictness(),
                encryption_info,
                encryption_contexts,
                segments: Mutex::new(segments),
                segment_handle_available: Condvar::new(),
                positioned_sources,
                index,
                chunk_cache: Mutex::new(LruCache::new(cache_size)),
                chunk_in_flight: Mutex::new(HashMap::new()),
                chunk_cache_capacity_bytes,
                table_page_cache: Mutex::new(TablePageCache::new(
                    options.table_entry_cache_size_bytes(),
                )),
                statistics,
                checksum_errors: Mutex::new(Vec::new()),
                defects: leniency.into_defects(),
                read_zero_chunk_on_error: AtomicBool::new(options.read_zero_chunk_on_error()),
                abort_signaled: AtomicBool::new(false),
            }),
        };
        if image
            .encryption_info()
            .is_some_and(|info| !info.password_verifier_present())
            && image.info().logical_size > 0
        {
            image.read_data_chunk(0)?;
        }
        Ok(image)
    }

    /// Defects recorded while opening.
    #[cfg(feature = "verify")]
    pub(crate) fn defects(&self) -> Vec<Defect> {
        self.inner.defects.clone()
    }

    /// Returns parsed image metadata and geometry.
    pub fn info(&self) -> &ImageInfo {
        &self.inner.info
    }

    /// Returns descriptor summaries in segment order and parser traversal order.
    /// Summary offsets are segment-relative, not logical media offsets.
    pub fn sections(&self) -> &[SectionInfo] {
        &self.inner.sections
    }

    /// Returns the structural policy used when opening this image.
    pub fn open_strictness(&self) -> OpenStrictness {
        self.inner.open_strictness
    }

    /// Returns non-secret encryption status for the opened image.
    #[must_use]
    pub fn encryption_info(&self) -> Option<EncryptionInfo> {
        self.inner.encryption_info
    }

    /// Returns cumulative reader counters when statistics were enabled at open time.
    ///
    /// Snapshots are shared across clones and cursors created from this image.
    pub fn reader_statistics(&self) -> Option<ReaderStatistics> {
        self.inner.statistics.snapshot()
    }

    /// Returns configured capacities and retained table-page payload bytes.
    pub fn reader_cache_info(&self) -> ReaderCacheInfo {
        let cache = self
            .inner
            .table_page_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ReaderCacheInfo::new(
            self.inner.chunk_cache_capacity_bytes,
            cache.capacity_bytes(),
            cache.cached_bytes(),
            cache.peak_bytes(),
        )
    }

    /// Returns the first segment filename or supplied-reader label.
    pub fn filename(&self) -> &Path {
        self.inner.info.segment_paths[0].as_path()
    }

    /// Returns the number of segments in the opened image.
    pub fn number_of_segments(&self) -> usize {
        self.inner.info.segment_count
    }

    /// Returns the configured maximum number of open segment handles.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal segment pool lock is poisoned.
    pub fn maximum_number_of_open_handles(&self) -> Result<Option<usize>> {
        Ok(self
            .inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?
            .maximum_open_handles())
    }

    /// Updates the maximum number of open segment handles.
    ///
    /// `None` allows all handles to remain open. Supplied-reader images cannot
    /// evict and reopen readers, so this value is validated against the reader
    /// set.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is invalid for supplied readers or if the
    /// internal segment pool lock is poisoned.
    pub fn set_maximum_number_of_open_handles(
        &self,
        maximum_open_handles: Option<usize>,
    ) -> Result<()> {
        self.inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?
            .set_maximum_open_handles(maximum_open_handles)
    }

    /// Returns the current number of open segment handles.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal segment pool lock is poisoned.
    pub fn number_of_open_segment_handles(&self) -> Result<usize> {
        Ok(self
            .inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?
            .open_count())
    }

    /// Returns all segment filenames or supplied-reader labels.
    pub fn segment_filenames(&self) -> &[PathBuf] {
        &self.inner.info.segment_paths
    }

    /// Returns one segment filename or supplied-reader label by index.
    pub fn segment_filename(&self, index: usize) -> Option<&Path> {
        self.inner
            .info
            .segment_paths
            .get(index)
            .map(PathBuf::as_path)
    }

    /// Returns the total byte size of all opened segment containers.
    ///
    /// For supplied readers, this uses [`SegmentReader::segment_len`].
    ///
    /// # Errors
    ///
    /// Returns an error if a segment length cannot be read, the internal segment
    /// pool lock is poisoned, or the total size overflows `u64`.
    pub fn segment_set_size(&self) -> Result<u64> {
        let paths = self.inner.info.segment_paths.clone();
        let mut segments = self
            .inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?;
        let mut size = 0_u64;
        for (segment_index, path) in paths.iter().enumerate() {
            size = size
                .checked_add(
                    segments
                        .file_mut(segment_index, path)?
                        .as_reader_mut()
                        .segment_len()?,
                )
                .ok_or_else(|| EwfError::Malformed("segment set size overflow".into()))?;
        }
        Ok(size)
    }

    /// Probes path-backed segment files for corruption-style structural errors.
    ///
    /// Images opened from supplied readers return `false` because there are no
    /// filesystem paths to reprobe.
    ///
    /// # Errors
    ///
    /// Returns an error if a path-backed probe fails unexpectedly.
    pub fn segment_files_corrupted(&self) -> Result<bool> {
        if self.has_supplied_segment_readers()? {
            return Ok(false);
        }
        check_segment_files_corruption(self.segment_filenames())
    }

    /// Probes path-backed segment files for EWF2 encryption markers.
    ///
    /// Images opened from supplied readers return `false` because there are no
    /// filesystem paths to reprobe.
    ///
    /// # Errors
    ///
    /// Returns an error if a path-backed probe fails unexpectedly.
    pub fn segment_files_encrypted(&self) -> Result<bool> {
        if self.has_supplied_segment_readers()? {
            return Ok(false);
        }
        check_segment_files_encryption(self.segment_filenames())
    }

    /// Returns the segment containing a logical chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if `chunk_index` is outside the parsed chunk index or if
    /// the chunk index references a missing segment.
    pub fn segment_filename_for_chunk(&self, chunk_index: u64) -> Result<&Path> {
        let chunk = self.lookup_chunk(chunk_index)?;
        self.segment_filename(chunk.segment_index)
            .ok_or_else(|| EwfError::Malformed("chunk references missing segment".into()))
    }

    /// Returns the segment containing a logical byte offset.
    ///
    /// Offsets at or beyond the logical media size return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk geometry is malformed.
    pub fn segment_filename_for_offset(&self, offset: u64) -> Result<Option<&Path>> {
        if offset >= self.inner.info.logical_size {
            return Ok(None);
        }
        let chunk_size = self.inner.info.chunk_size;
        if chunk_size == 0 {
            return Err(EwfError::Malformed("chunk size is zero".into()));
        }
        self.segment_filename_for_chunk(offset / chunk_size)
            .map(Some)
    }

    /// Returns the top-level EWF format generation.
    pub fn format(&self) -> Format {
        self.inner.info.format
    }

    /// Returns the inferred format profile.
    pub fn format_profile(&self) -> FormatProfile {
        self.inner.info.format_profile
    }

    /// Returns the logical chunk size in bytes.
    pub fn chunk_size(&self) -> u64 {
        self.inner.info.chunk_size
    }

    /// Returns the logical media size in bytes.
    pub fn media_size(&self) -> u64 {
        self.inner.info.logical_size
    }

    /// Returns the header codepage used for decoded EWF1 values.
    pub fn header_codepage(&self) -> HeaderCodepage {
        self.inner.info.header_codepage
    }

    /// Returns the date format applied to header date values.
    pub fn header_values_date_format(&self) -> HeaderDateFormat {
        self.inner.info.header_values_date_format
    }

    /// Returns sectors per chunk from media metadata.
    pub fn sectors_per_chunk(&self) -> Option<u64> {
        self.inner.info.media.sectors_per_chunk
    }

    /// Returns bytes per sector from media metadata.
    pub fn bytes_per_sector(&self) -> Option<u64> {
        self.inner.info.media.bytes_per_sector
    }

    /// Returns the logical sector count from media metadata.
    pub fn number_of_sectors(&self) -> Option<u64> {
        self.inner.info.media.sector_count
    }

    /// Returns the logical chunk count from media metadata.
    pub fn number_of_chunks(&self) -> Option<u64> {
        self.inner.info.media.chunk_count
    }

    /// Returns error granularity in sectors from media metadata.
    pub fn error_granularity(&self) -> Option<u64> {
        self.inner.info.media.error_granularity
    }

    /// Returns the segment set identifier.
    pub fn segment_file_set_identifier(&self) -> Option<[u8; 16]> {
        self.inner.info.media.set_identifier
    }

    /// Returns the EWF2 segment file version.
    pub fn segment_file_version(&self) -> Option<SegmentFileVersion> {
        self.inner.info.media.ewf2_segment_file_version
    }

    /// Returns the stored compression method metadata.
    pub fn compression_method(&self) -> Option<CompressionMethod> {
        self.inner.info.media.compression_method
    }

    /// Returns stored compression level and flags metadata.
    pub fn compression_values(&self) -> CompressionValues {
        self.inner.info.media.compression_values
    }

    /// Returns media type metadata.
    pub fn media_type(&self) -> Option<MediaType> {
        self.inner.info.media.media_type
    }

    /// Returns media flag metadata.
    pub fn media_flags(&self) -> MediaFlags {
        self.inner.info.media.media_flags
    }

    /// Returns memory acquisition extents.
    pub fn memory_extents(&self) -> &[MemoryExtent] {
        &self.inner.info.memory_extents
    }

    /// Returns the number of memory acquisition extents.
    pub fn number_of_memory_extents(&self) -> usize {
        self.inner.info.memory_extents.len()
    }

    /// Returns one memory acquisition extent by index.
    pub fn memory_extent(&self, index: usize) -> Option<&MemoryExtent> {
        self.inner.info.memory_extents.get(index)
    }

    /// Returns raw EWF2 increment data sections.
    pub fn ewf2_increment_data(&self) -> &[Vec<u8>] {
        &self.inner.info.ewf2_increment_data
    }

    /// Returns the number of EWF2 increment data sections.
    pub fn number_of_ewf2_increment_data_sections(&self) -> usize {
        self.inner.info.ewf2_increment_data.len()
    }

    /// Returns one raw EWF2 increment data section by index.
    pub fn ewf2_increment_data_section(&self, index: usize) -> Option<&[u8]> {
        self.inner
            .info
            .ewf2_increment_data
            .get(index)
            .map(Vec::as_slice)
    }

    /// Returns the raw EWF2 final information section.
    pub fn ewf2_final_information(&self) -> Option<&[u8]> {
        self.inner.info.ewf2_final_information.as_deref()
    }

    /// Returns EWF2 restart data text.
    pub fn ewf2_restart_data(&self) -> Option<&str> {
        self.inner.info.ewf2_restart_data.as_deref()
    }

    /// Returns EWF2 analytical data text.
    pub fn ewf2_analytical_data(&self) -> Option<&str> {
        self.inner.info.ewf2_analytical_data.as_deref()
    }

    /// Returns a header value by its EWF identifier.
    pub fn header_value(&self, identifier: &str) -> Option<std::borrow::Cow<'_, str>> {
        self.inner
            .info
            .metadata
            .header_value_with_date_format(identifier, self.inner.info.header_values_date_format)
    }

    /// Returns the number of available header values.
    pub fn number_of_header_values(&self) -> usize {
        self.inner.info.metadata.number_of_header_values()
    }

    /// Returns a header value identifier by enumeration index.
    pub fn header_value_identifier(&self, index: usize) -> Option<&str> {
        self.inner.info.metadata.header_value_identifier(index)
    }

    /// Returns a stored hash string by identifier.
    pub fn hash_value(&self, identifier: &str) -> Option<&str> {
        self.inner.info.stored_hashes.hash_value(identifier)
    }

    /// Returns the number of stored hash strings.
    pub fn number_of_hash_values(&self) -> usize {
        self.inner.info.stored_hashes.number_of_hash_values()
    }

    /// Returns a stored hash identifier by enumeration index.
    pub fn hash_value_identifier(&self, index: usize) -> Option<&str> {
        self.inner.info.stored_hashes.hash_value_identifier(index)
    }

    /// Returns a seekable cursor over the logical media stream.
    pub fn cursor(&self) -> ImageCursor {
        self.inner.statistics.record_cursor_created();
        ImageCursor {
            image: self.clone(),
            position: 0,
        }
    }

    /// Reads logical media bytes at an absolute byte offset.
    ///
    /// Returns `Ok(0)` when `buf` is empty or `offset` is at or beyond the
    /// logical media size.
    ///
    /// # Errors
    ///
    /// Returns an error if chunk lookup, decoding, checksum validation, or
    /// segment I/O fails, or if [`Image::signal_abort`] has been called.
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.read_at_impl(buf, offset, false)
    }

    fn read_at_impl(&self, buf: &mut [u8], offset: u64, strict: bool) -> Result<usize> {
        self.ensure_not_aborted()?;
        if buf.is_empty() || offset >= self.inner.info.logical_size {
            return Ok(0);
        }

        let chunk_size = self.inner.info.chunk_size;
        if chunk_size == 0 {
            return Err(EwfError::Malformed("chunk size is zero".into()));
        }

        let available = self.inner.info.logical_size - offset;
        let requested = u64::try_from(buf.len())
            .map_err(|_| EwfError::Malformed("read buffer length does not fit u64".into()))?;
        let to_read = available.min(requested);
        let mut copied = 0_usize;
        let mut current = offset;

        while u64::try_from(copied).expect("usize fits u64") < to_read {
            self.ensure_not_aborted()?;
            let chunk_id = current / chunk_size;
            let page_offset = usize::try_from(current % chunk_size)
                .map_err(|_| EwfError::Malformed("page offset does not fit usize".into()))?;
            let decoded = if strict {
                Arc::new(self.verification_chunk(chunk_id)?)
            } else {
                self.read_chunk(chunk_id)?
            };
            let remaining =
                usize::try_from(to_read - u64::try_from(copied).unwrap()).map_err(|_| {
                    EwfError::Malformed("remaining read size does not fit usize".into())
                })?;
            let page_available = decoded.len().saturating_sub(page_offset);
            let n = remaining.min(page_available);
            if n == 0 {
                break;
            }

            buf[copied..copied + n].copy_from_slice(&decoded[page_offset..page_offset + n]);
            copied += n;
            current += u64::try_from(n).expect("usize fits u64");
        }

        Ok(copied)
    }

    /// Alias for [`Image::read_at`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Image::read_at`].
    pub fn read_buffer_at_offset(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.read_at(buf, offset)
    }

    /// Reads bytes from a logical single-file catalog entry.
    ///
    /// Sparse extents read as zeroes. EWF1 logical sparse entries repeat a
    /// stored byte or read from their duplicate offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry metadata is inconsistent, the requested
    /// file range is not covered by extents, underlying image reads fail, or
    /// [`Image::signal_abort`] has been called.
    pub fn read_single_file_at(
        &self,
        entry: &SingleFileEntry,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
        self.read_single_file_at_impl(entry, buf, offset, false)
    }

    /// Reads a logical file with strict chunk validation, bypassing decoded
    /// caches and the zero-on-error policy. Sparse entry handling is unchanged.
    /// Does not verify stored file hashes; use `verify_single_file` for that.
    pub fn read_single_file_at_strict(
        &self,
        entry: &SingleFileEntry,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
        self.read_single_file_at_impl(entry, buf, offset, true)
    }

    fn read_single_file_at_impl(
        &self,
        entry: &SingleFileEntry,
        buf: &mut [u8],
        offset: u64,
        strict: bool,
    ) -> Result<usize> {
        self.ensure_not_aborted()?;
        if buf.is_empty() {
            return Ok(0);
        }

        let file_size = single_file_size(entry)?;
        if offset >= file_size {
            return Ok(0);
        }

        let requested = u64::try_from(buf.len())
            .map_err(|_| EwfError::Malformed("read buffer length does not fit u64".into()))?;
        let to_read = requested.min(file_size - offset);
        let mut copied = 0_usize;
        let mut file_position = 0_u64;
        let ewf1_logical_sparse = self.inner.info.format == Format::Ewf1
            && matches!(
                self.inner.info.format_profile,
                FormatProfile::LogicalEnCase5
                    | FormatProfile::LogicalEnCase6
                    | FormatProfile::LogicalEnCase7
            )
            && entry
                .flags
                .is_some_and(|flags| flags & EWF1_LOGICAL_SPARSE_FLAG != 0);

        if (entry.extents.is_empty() || ewf1_logical_sparse)
            && let Some(duplicate_data_offset) = entry.duplicate_data_offset
            && duplicate_data_offset >= 0
        {
            let duplicate_data_offset = u64::try_from(duplicate_data_offset).map_err(|_| {
                EwfError::Malformed("single file duplicate data offset does not fit u64".into())
            })?;
            let image_offset = duplicate_data_offset.checked_add(offset).ok_or_else(|| {
                EwfError::Malformed("single file duplicate data offset overflow".into())
            })?;
            let read_size = usize::try_from(to_read).map_err(|_| {
                EwfError::Malformed("single file duplicate read size does not fit usize".into())
            })?;
            let out = &mut buf[..read_size];
            let read = self.read_at_impl(out, image_offset, strict)?;
            if read != read_size {
                return Err(EwfError::Malformed(
                    "single file duplicate data read was truncated".into(),
                ));
            }
            return Ok(read);
        }

        if ewf1_logical_sparse {
            let extent = entry
                .extents
                .first()
                .filter(|extent| !extent.sparse && extent.data_size >= 1)
                .ok_or_else(|| {
                    EwfError::Malformed("single file sparse entry has no stored byte".into())
                })?;
            let mut byte = [0_u8; 1];
            if self.read_at_impl(&mut byte, extent.data_offset, strict)? != 1 {
                return Err(EwfError::Malformed(
                    "single file sparse entry stored byte was truncated".into(),
                ));
            }
            let read_size = usize::try_from(to_read).map_err(|_| {
                EwfError::Malformed("single file sparse read size does not fit usize".into())
            })?;
            buf[..read_size].fill(byte[0]);
            return Ok(read_size);
        }

        for extent in &entry.extents {
            let extent_start = file_position;
            let extent_end = extent_start
                .checked_add(extent.data_size)
                .ok_or_else(|| EwfError::Malformed("single file extent range overflow".into()))?;
            file_position = extent_end;

            let read_start = offset.max(extent_start);
            let read_end = (offset + to_read).min(extent_end);
            if read_start >= read_end {
                continue;
            }

            let extent_relative_offset = read_start
                .checked_sub(extent_start)
                .ok_or_else(|| EwfError::Malformed("single file extent offset underflow".into()))?;
            let output_offset = usize::try_from(read_start - offset).map_err(|_| {
                EwfError::Malformed("single file output offset does not fit usize".into())
            })?;
            let read_size = usize::try_from(read_end - read_start).map_err(|_| {
                EwfError::Malformed("single file read size does not fit usize".into())
            })?;
            let out = &mut buf[output_offset..output_offset + read_size];

            if extent.sparse {
                out.fill(0);
                copied += read_size;
                continue;
            }

            let image_offset = extent
                .data_offset
                .checked_add(extent_relative_offset)
                .ok_or_else(|| {
                    EwfError::Malformed("single file extent data offset overflow".into())
                })?;
            let read = self.read_at_impl(out, image_offset, strict)?;
            if read != read_size {
                return Err(EwfError::Malformed(
                    "single file extent read was truncated".into(),
                ));
            }
            copied += read_size;
        }

        if u64::try_from(copied).expect("usize fits u64") != to_read {
            return Err(EwfError::Malformed(
                "single file extents do not cover requested range".into(),
            ));
        }
        Ok(copied)
    }

    /// Alias for [`Image::read_single_file_at`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Image::read_single_file_at`].
    pub fn read_file_entry_at(
        &self,
        entry: &SingleFileEntry,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize> {
        self.read_single_file_at(entry, buf, offset)
    }

    /// Returns the root logical single-file entry, if present.
    pub fn root_file_entry(&self) -> Option<&SingleFileEntry> {
        self.inner
            .info
            .single_files
            .as_ref()
            .map(|single_files| &single_files.root)
    }

    /// Returns a logical single-file entry by path.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` contains an empty entry name.
    pub fn file_entry_by_path(&self, path: &str) -> Result<Option<&SingleFileEntry>> {
        self.inner
            .info
            .single_files
            .as_ref()
            .map_or(Ok(None), |single_files| single_files.entry_by_path(path))
    }

    /// Returns the source record associated with a logical single-file entry.
    pub fn source_for_file_entry(&self, entry: &SingleFileEntry) -> Option<&SingleFileSource> {
        self.inner
            .info
            .single_files
            .as_ref()?
            .source_for_entry(entry)
    }

    /// Returns the subject record associated with a logical single-file entry.
    pub fn subject_for_file_entry(&self, entry: &SingleFileEntry) -> Option<&SingleFileSubject> {
        self.inner
            .info
            .single_files
            .as_ref()?
            .subject_for_entry(entry)
    }

    /// Returns access-control entries associated with a logical single-file entry.
    pub fn access_control_entries_for_file_entry(
        &self,
        entry: &SingleFileEntry,
    ) -> &[SingleFilePermission] {
        self.inner
            .info
            .single_files
            .as_ref()
            .map_or(&[], |single_files| {
                single_files.access_control_entries_for_entry(entry)
            })
    }

    /// Returns the number of access-control entries for a logical single-file entry.
    pub fn number_of_access_control_entries_for_file_entry(
        &self,
        entry: &SingleFileEntry,
    ) -> usize {
        self.access_control_entries_for_file_entry(entry).len()
    }

    /// Returns one access-control entry for a logical single-file entry by index.
    pub fn access_control_entry_for_file_entry(
        &self,
        entry: &SingleFileEntry,
        index: usize,
    ) -> Option<&SingleFilePermission> {
        self.access_control_entries_for_file_entry(entry).get(index)
    }

    /// Returns the stored MD5 hash bytes.
    pub fn md5_hash(&self) -> Option<[u8; 16]> {
        self.inner.info.stored_hashes.md5
    }

    /// Returns the stored SHA1 hash bytes.
    pub fn sha1_hash(&self) -> Option<[u8; 20]> {
        self.inner.info.stored_hashes.sha1
    }

    /// Returns acquisition error ranges.
    pub fn acquisition_errors(&self) -> &[AcquisitionError] {
        &self.inner.info.acquisition_errors
    }

    /// Returns the number of acquisition error ranges.
    pub fn number_of_acquisition_errors(&self) -> usize {
        self.inner.info.acquisition_errors.len()
    }

    /// Returns one acquisition error range by index.
    pub fn acquisition_error(&self, index: usize) -> Option<&AcquisitionError> {
        self.inner.info.acquisition_errors.get(index)
    }

    /// Returns session sector ranges.
    pub fn sessions(&self) -> &[SectorRange] {
        &self.inner.info.sessions
    }

    /// Returns the number of session sector ranges.
    pub fn number_of_sessions(&self) -> usize {
        self.inner.info.sessions.len()
    }

    /// Returns one session sector range by index.
    pub fn session(&self, index: usize) -> Option<&SectorRange> {
        self.inner.info.sessions.get(index)
    }

    /// Returns track sector ranges.
    pub fn tracks(&self) -> &[SectorRange] {
        &self.inner.info.tracks
    }

    /// Returns the number of track sector ranges.
    pub fn number_of_tracks(&self) -> usize {
        self.inner.info.tracks.len()
    }

    /// Returns one track sector range by index.
    pub fn track(&self, index: usize) -> Option<&SectorRange> {
        self.inner.info.tracks.get(index)
    }

    /// Returns whether checksum-failed chunks are read as zero-filled data.
    pub fn read_zero_chunk_on_error(&self) -> bool {
        self.inner.read_zero_chunk_on_error.load(Ordering::Relaxed)
    }

    /// Sets whether checksum-failed chunks are read as zero-filled data.
    pub fn set_read_zero_chunk_on_error(&self, zero_on_error: bool) {
        self.inner
            .read_zero_chunk_on_error
            .store(zero_on_error, Ordering::Relaxed);
    }

    /// Signals future reads and verification to abort with [`EwfError::Aborted`].
    pub fn signal_abort(&self) {
        self.inner.abort_signaled.store(true, Ordering::Relaxed);
    }

    /// Returns checksum error ranges observed while reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal checksum-error lock is poisoned.
    pub fn checksum_errors(&self) -> Result<Vec<SectorRange>> {
        Ok(self
            .inner
            .checksum_errors
            .lock()
            .map_err(|_| EwfError::Malformed("checksum errors lock poisoned".into()))?
            .clone())
    }

    /// Returns the number of checksum error ranges observed while reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal checksum-error lock is poisoned.
    pub fn number_of_checksum_errors(&self) -> Result<usize> {
        Ok(self
            .inner
            .checksum_errors
            .lock()
            .map_err(|_| EwfError::Malformed("checksum errors lock poisoned".into()))?
            .len())
    }

    /// Returns one checksum error range observed while reading.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal checksum-error lock is poisoned.
    pub fn checksum_error(&self, index: usize) -> Result<Option<SectorRange>> {
        Ok(self
            .inner
            .checksum_errors
            .lock()
            .map_err(|_| EwfError::Malformed("checksum errors lock poisoned".into()))?
            .get(index)
            .cloned())
    }

    /// Returns a seekable cursor over a logical single-file entry.
    pub fn single_file_cursor(&self, entry: &SingleFileEntry) -> SingleFileCursor {
        self.inner.statistics.record_cursor_created();
        SingleFileCursor {
            image: self.clone(),
            entry: entry.clone(),
            position: 0,
        }
    }

    /// Returns a seekable cursor over a logical single-file entry by path.
    ///
    /// # Errors
    ///
    /// Returns an error if `path` contains an empty entry name.
    pub fn single_file_cursor_by_path(&self, path: &str) -> Result<Option<SingleFileCursor>> {
        self.file_entry_by_path(path)
            .map(|entry| entry.map(|entry| self.single_file_cursor(entry)))
    }

    /// Reads and decodes one logical data chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk index is invalid, segment I/O fails,
    /// decoding fails, checksum validation fails under the current policy, or
    /// [`Image::signal_abort`] has been called.
    pub fn read_data_chunk(&self, chunk_index: u64) -> Result<DataChunk> {
        self.ensure_not_aborted()?;
        let chunk = self.lookup_chunk(chunk_index)?;
        let (data, corrupted) = self.decode_chunk_with_policy(chunk_index, chunk)?;
        let logical_offset = chunk_index
            .checked_mul(self.inner.info.chunk_size)
            .ok_or_else(|| EwfError::Malformed("data chunk logical offset overflow".into()))?;

        Ok(DataChunk {
            chunk_index,
            logical_offset,
            logical_size: chunk.logical_size,
            encoded_size: chunk.encoded_size,
            encoding: data_chunk_encoding(chunk.encoding),
            corrupted,
            data,
        })
    }

    /// Reads one encoded data chunk without decoding the payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk index is invalid, segment I/O fails, or
    /// [`Image::signal_abort`] has been called.
    pub fn read_encoded_data_chunk(&self, chunk_index: u64) -> Result<EncodedDataChunk> {
        self.ensure_not_aborted()?;
        let chunk = self.lookup_chunk(chunk_index)?;
        let data = self.read_encoded_chunk_bytes(chunk_index, chunk)?;
        let logical_offset = chunk_index
            .checked_mul(self.inner.info.chunk_size)
            .ok_or_else(|| EwfError::Malformed("data chunk logical offset overflow".into()))?;

        Ok(EncodedDataChunk {
            chunk_index,
            logical_offset,
            logical_size: chunk.logical_size,
            encoded_size: chunk.encoded_size,
            encoding: data_chunk_encoding(chunk.encoding),
            has_checksum: chunk.validate_checksum,
            data,
        })
    }

    fn read_chunk(&self, chunk_id: u64) -> Result<Arc<Vec<u8>>> {
        self.ensure_not_aborted()?;
        let mut first_cache_check = true;
        loop {
            let cached = self
                .inner
                .chunk_cache
                .lock()
                .map_err(|_| EwfError::Malformed("chunk cache lock poisoned".into()))?
                .get(&chunk_id)
                .cloned();
            if first_cache_check {
                self.inner
                    .statistics
                    .record_chunk_cache_access(cached.is_some());
                first_cache_check = false;
            }
            if let Some(cached) = cached {
                return Ok(cached);
            }

            let (flight, decode_here) = {
                let mut in_flight = self
                    .inner
                    .chunk_in_flight
                    .lock()
                    .map_err(|_| EwfError::Malformed("chunk flight lock poisoned".into()))?;
                if let Some(flight) = in_flight.get(&chunk_id) {
                    (Arc::clone(flight), false)
                } else {
                    let flight = Arc::new(ChunkFlight {
                        complete: Mutex::new(false),
                        ready: Condvar::new(),
                    });
                    in_flight.insert(chunk_id, Arc::clone(&flight));
                    (flight, true)
                }
            };

            if !decode_here {
                self.inner.statistics.record_chunk_cache_coalesced();
                let mut complete = flight
                    .complete
                    .lock()
                    .map_err(|_| EwfError::Malformed("chunk flight lock poisoned".into()))?;
                while !*complete {
                    complete = flight
                        .ready
                        .wait(complete)
                        .map_err(|_| EwfError::Malformed("chunk flight lock poisoned".into()))?;
                }
                continue;
            }

            let decoded = (|| {
                let chunk = self.lookup_chunk(chunk_id)?;
                let (decoded, _) = self.decode_chunk_with_policy(chunk_id, chunk)?;
                let decoded = Arc::new(decoded);
                self.inner
                    .chunk_cache
                    .lock()
                    .map_err(|_| EwfError::Malformed("chunk cache lock poisoned".into()))?
                    .put(chunk_id, Arc::clone(&decoded));
                Ok(decoded)
            })();
            let mut complete = flight
                .complete
                .lock()
                .map_err(|_| EwfError::Malformed("chunk flight lock poisoned".into()))?;
            *complete = true;
            flight.ready.notify_all();
            drop(complete);
            self.inner
                .chunk_in_flight
                .lock()
                .map_err(|_| EwfError::Malformed("chunk flight lock poisoned".into()))?
                .remove(&chunk_id);
            return decoded;
        }
    }

    fn lookup_chunk(&self, chunk_id: u64) -> Result<Chunk> {
        let (_, range) = self.inner.index.range_index_for(chunk_id)?;
        let local_index = chunk_id
            .checked_sub(range.first_chunk)
            .ok_or_else(|| EwfError::Malformed("chunk range underflow".into()))?;
        let logical_size = logical_chunk_size(
            self.inner.info.logical_size,
            self.inner.info.chunk_size,
            chunk_id,
        )?;

        match range.kind {
            TableRangeKind::Ewf1 => self.lookup_ewf1_chunk(range, local_index, logical_size),
            TableRangeKind::Ewf2 => self.lookup_ewf2_chunk(range, local_index, logical_size),
        }
    }

    fn lookup_ewf1_chunk(
        &self,
        range: &TableRange,
        local_index: u64,
        logical_size: usize,
    ) -> Result<Chunk> {
        let raw = self.read_u32_at(
            range.segment_index,
            table_entry_offset(range, local_index, 4)?,
        )?;
        let next_raw = if local_index + 1 < range.chunk_count {
            Some(self.read_u32_at(
                range.segment_index,
                table_entry_offset(range, local_index + 1, 4)?,
            )?)
        } else {
            None
        };
        let entry = decode_ewf1_entry(
            range,
            raw,
            self.inner.info.chunk_size,
            next_raw,
            local_index + 1 == range.chunk_count,
        )?;

        let next_offset = if let Some(next_raw) = next_raw {
            decode_ewf1_entry(
                range,
                next_raw,
                self.inner.info.chunk_size,
                None,
                local_index + 2 == range.chunk_count,
            )?
            .offset
        } else {
            range
                .data_end
                .ok_or_else(|| EwfError::Malformed("EWF1 table range has no data end".into()))?
        };

        if next_offset <= entry.offset {
            return Err(EwfError::Malformed(
                "EWF1 chunk offsets are not ordered".into(),
            ));
        }
        let encoded_size = next_offset - entry.offset;
        let compression_method = range.ewf1_compression_method.ok_or_else(|| {
            EwfError::Malformed("EWF1 table range has no compression method".into())
        })?;
        let encoding = ewf1_chunk_encoding(
            entry.compressed,
            encoded_size,
            self.inner.info.chunk_size,
            compression_method,
        )?;
        validate_ewf1_encoded_size(
            encoded_size,
            self.inner.info.chunk_size,
            encoding,
            range.ewf1_allow_large_compressed_chunks,
        )?;
        Ok(Chunk {
            segment_index: range.segment_index,
            offset: entry.offset,
            encoded_size,
            logical_size,
            encoding,
            validate_checksum: encoding == ChunkEncoding::Raw
                && u64::try_from(logical_size)
                    .ok()
                    .and_then(|size| size.checked_add(4))
                    == Some(encoded_size),
        })
    }

    fn lookup_ewf2_chunk(
        &self,
        range: &TableRange,
        local_index: u64,
        logical_size: usize,
    ) -> Result<Chunk> {
        let entry_offset = table_entry_offset(range, local_index, ewf2::TABLE_ENTRY_SIZE as u64)?;
        let entry_data = self.read_table_bytes_at(
            range.segment_index,
            entry_offset,
            ewf2::TABLE_ENTRY_SIZE as u64,
        )?;
        let compression_method = range
            .ewf2_compression_method
            .map(ewf2::CompressionMethod::from)
            .ok_or_else(|| EwfError::Malformed("EWF2 range has no compression method".into()))?;
        let entry = ewf2::TableEntry::parse(&entry_data, compression_method)?;
        let encoding = match entry.kind {
            ewf2::ChunkKind::Raw | ewf2::ChunkKind::Compressed(ewf2::CompressionMethod::None) => {
                ChunkEncoding::Raw
            }
            ewf2::ChunkKind::Compressed(ewf2::CompressionMethod::Zlib) => ChunkEncoding::Zlib,
            ewf2::ChunkKind::Compressed(ewf2::CompressionMethod::Bzip2) => ChunkEncoding::Bzip2,
            ewf2::ChunkKind::Compressed(ewf2::CompressionMethod::Unknown(method)) => {
                return Err(EwfError::Unsupported(format!(
                    "unknown EWF2 compression method {method}"
                )));
            }
            ewf2::ChunkKind::PatternFill => ChunkEncoding::PatternFill(entry.chunk_data_offset),
        };
        let validate_checksum = matches!(encoding, ChunkEncoding::Raw)
            && entry.flags & ewf2::CHUNK_FLAG_HAS_CHECKSUM != 0;
        validate_encoded_size(
            u64::from(entry.chunk_data_size),
            self.inner.info.chunk_size,
            encoding,
        )?;
        Ok(Chunk {
            segment_index: range.segment_index,
            offset: entry.chunk_data_offset,
            encoded_size: u64::from(entry.chunk_data_size),
            logical_size,
            encoding,
            validate_checksum,
        })
    }

    fn read_u32_at(&self, segment_index: usize, offset: u64) -> Result<u32> {
        let data = self.read_table_bytes_at(segment_index, offset, 4)?;
        Ok(u32::from_le_bytes(
            data[..4].try_into().expect("slice length checked"),
        ))
    }

    fn read_table_bytes_at(&self, segment_index: usize, offset: u64, size: u64) -> Result<Vec<u8>> {
        let requested = usize::try_from(size)
            .map_err(|_| EwfError::Malformed("table read size does not fit usize".into()))?;
        let cache_disabled = self
            .inner
            .table_page_cache
            .lock()
            .map_err(|_| EwfError::Malformed("table page cache lock poisoned".into()))?
            .is_disabled();
        if cache_disabled {
            self.inner.statistics.record_table_page_cache_access(false);
            return self.read_segment_range(segment_index, offset, size, false);
        }
        let mut output = Vec::with_capacity(requested);
        let mut current = offset;
        while output.len() < requested {
            let page_offset = current - current % TABLE_PAGE_SIZE;
            let key = TablePageKey {
                segment_index,
                page_offset,
            };
            let cached = self
                .inner
                .table_page_cache
                .lock()
                .map_err(|_| EwfError::Malformed("table page cache lock poisoned".into()))?
                .get(&key);
            self.inner
                .statistics
                .record_table_page_cache_access(cached.is_some());
            let page = if let Some(page) = cached {
                page
            } else {
                let bytes =
                    self.read_segment_range(segment_index, page_offset, TABLE_PAGE_SIZE, true)?;
                self.inner
                    .table_page_cache
                    .lock()
                    .map_err(|_| EwfError::Malformed("table page cache lock poisoned".into()))?
                    .insert(key, bytes)
            };
            let within_page = usize::try_from(current - page_offset)
                .map_err(|_| EwfError::Malformed("table page offset does not fit usize".into()))?;
            let available = page.len().saturating_sub(within_page);
            if available == 0 {
                return Err(EwfError::Malformed("table read crosses segment end".into()));
            }
            let take = available.min(requested - output.len());
            output.extend_from_slice(&page[within_page..within_page + take]);
            current = current
                .checked_add(u64::try_from(take).expect("usize fits u64"))
                .ok_or_else(|| EwfError::Malformed("table read offset overflow".into()))?;
        }
        Ok(output)
    }

    pub(crate) fn ensure_not_aborted(&self) -> Result<()> {
        if self.inner.abort_signaled.load(Ordering::Relaxed) {
            return Err(EwfError::Aborted);
        }
        Ok(())
    }

    pub(crate) fn read_segment_range(
        &self,
        segment_index: usize,
        offset: u64,
        size: u64,
        clamp: bool,
    ) -> Result<Vec<u8>> {
        let bounded_size = |length: u64| -> Result<u64> {
            if clamp {
                let size = size.min(length.saturating_sub(offset));
                if size == 0 {
                    return Err(EwfError::Malformed(
                        "table page starts beyond segment end".into(),
                    ));
                }
                return Ok(size);
            }
            if offset.checked_add(size).is_none_or(|end| end > length) {
                return Err(EwfError::Malformed(
                    "requested byte range exceeds segment size".into(),
                ));
            }
            Ok(size)
        };
        if let Some(sources) = &self.inner.positioned_sources {
            let source = sources
                .get(segment_index)
                .ok_or_else(|| EwfError::Malformed("missing segment source".into()))?;
            let size = bounded_size(source.len())?;
            let mut bytes = vec![
                0;
                usize::try_from(size).map_err(|_| EwfError::Malformed(
                    "segment read size exceeds usize".into()
                ))?
            ];
            source.read_exact_at(&mut bytes, offset)?;
            return Ok(bytes);
        }
        let path = self
            .inner
            .info
            .segment_paths
            .get(segment_index)
            .ok_or_else(|| EwfError::Malformed("missing segment source".into()))?;

        #[cfg(any(unix, windows))]
        if !self.has_supplied_segment_readers()? {
            let wait_started = Instant::now();
            let (file, length) = {
                let mut segments =
                    self.inner.segments.lock().map_err(|_| {
                        EwfError::Malformed("segment file pool lock poisoned".into())
                    })?;
                loop {
                    if let Some(file) = segments.acquire_path_file(segment_index, path)? {
                        let length = file.metadata()?.len();
                        break (file, length);
                    }
                    segments =
                        self.inner
                            .segment_handle_available
                            .wait(segments)
                            .map_err(|_| {
                                EwfError::Malformed("segment file pool lock poisoned".into())
                            })?;
                }
            };
            self.inner
                .statistics
                .record_segment_pool_wait(wait_started.elapsed());
            let lease = PositionedSegmentLease {
                file: Some(file),
                segments: &self.inner.segments,
                available: &self.inner.segment_handle_available,
            };
            let size = bounded_size(length)?;
            let mut bytes = vec![
                0;
                usize::try_from(size).map_err(|_| EwfError::Malformed(
                    "segment read size exceeds usize".into()
                ))?
            ];
            let read_started = Instant::now();
            read_file_exact_at(lease.file(), &mut bytes, offset)?;
            self.inner
                .statistics
                .record_segment_read(bytes.len(), read_started.elapsed());
            return Ok(bytes);
        }

        let mut segments = self
            .inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?;
        let size = bounded_size(segments.segment_len(segment_index, path)?)?;
        read_exact_at(
            segments.file_mut(segment_index, path)?.as_reader_mut(),
            offset,
            size,
        )
    }

    fn has_supplied_segment_readers(&self) -> Result<bool> {
        Ok(self
            .inner
            .segments
            .lock()
            .map_err(|_| EwfError::Malformed("segment file pool lock poisoned".into()))?
            .has_supplied_readers())
    }

    fn read_encoded_chunk_bytes(&self, chunk_id: u64, chunk: Chunk) -> Result<Vec<u8>> {
        self.ensure_not_aborted()?;
        if matches!(chunk.encoding, ChunkEncoding::PatternFill(_)) {
            return Ok(Vec::new());
        }

        let mut encoded =
            self.read_segment_range(chunk.segment_index, chunk.offset, chunk.encoded_size, false)?;
        self.inner
            .statistics
            .record_encoded_bytes_read(chunk.encoded_size);
        if let Some(context) = self
            .inner
            .encryption_contexts
            .get(chunk.segment_index)
            .and_then(Option::as_ref)
        {
            let stream_offset = chunk_id
                .checked_mul(self.inner.info.chunk_size)
                .ok_or_else(|| EwfError::Malformed("encrypted chunk offset overflow".into()))?;
            context.apply_keystream(stream_offset, &mut encoded)?;
        }
        Ok(encoded)
    }

    fn decode_chunk(&self, chunk_id: u64, chunk: Chunk) -> Result<Vec<u8>> {
        let encoded = self.read_encoded_chunk_bytes(chunk_id, chunk)?;
        if chunk.validate_checksum {
            validate_raw_chunk_checksum(&encoded, chunk.logical_size)?;
        }
        let decompression_started = (self.inner.statistics.enabled()
            && matches!(
                chunk.encoding,
                ChunkEncoding::Zlib | ChunkEncoding::Zstd | ChunkEncoding::Bzip2
            ))
        .then(Instant::now);
        let maximum_decoded_size = if self.inner.info.format == Format::Ewf1
            && matches!(
                self.inner.info.format_profile,
                FormatProfile::LogicalEnCase5
                    | FormatProfile::LogicalEnCase6
                    | FormatProfile::LogicalEnCase7
            ) {
            usize::try_from(self.inner.info.chunk_size)
                .map_err(|_| EwfError::Malformed("chunk size does not fit usize".into()))?
        } else {
            chunk.logical_size
        };
        let decoded = decode_chunk_with_padding(
            &encoded,
            chunk.encoding,
            chunk.logical_size,
            maximum_decoded_size,
        )?;
        if let Some(started) = decompression_started {
            self.inner
                .statistics
                .record_decompression(started.elapsed());
        }
        self.inner.statistics.record_decoded_bytes(decoded.len());
        Ok(decoded)
    }

    pub(crate) fn verification_chunk(&self, chunk_id: u64) -> Result<Vec<u8>> {
        self.ensure_not_aborted()?;
        let chunk = self.lookup_chunk(chunk_id)?;
        // Verification never consumes cached or zero-filled recovery bytes.
        self.decode_chunk(chunk_id, chunk).map_err(|error| {
            if matches!(error, EwfError::Malformed(_)) && self.encryption_info().is_some() {
                EwfError::DecryptionValidationFailed
            } else {
                error
            }
        })
    }

    fn decode_chunk_with_policy(&self, chunk_id: u64, chunk: Chunk) -> Result<(Vec<u8>, bool)> {
        match self.decode_chunk(chunk_id, chunk) {
            Ok(decoded) => Ok((decoded, false)),
            Err(EwfError::Malformed(_))
                if self
                    .inner
                    .encryption_contexts
                    .get(chunk.segment_index)
                    .is_some_and(Option::is_some) =>
            {
                Err(EwfError::DecryptionValidationFailed)
            }
            Err(EwfError::Malformed(_)) if self.read_zero_chunk_on_error() => {
                self.record_checksum_error(chunk_id, chunk.logical_size)?;
                Ok((vec![0; chunk.logical_size], true))
            }
            Err(err) => Err(err),
        }
    }

    fn record_checksum_error(&self, chunk_id: u64, logical_size: usize) -> Result<()> {
        let range = checksum_error_range(&self.inner.info, chunk_id, logical_size)?;
        let mut errors = self
            .inner
            .checksum_errors
            .lock()
            .map_err(|_| EwfError::Malformed("checksum errors lock poisoned".into()))?;
        if !errors.contains(&range) {
            errors.push(range);
        }
        Ok(())
    }
}

impl SegmentFilePool {
    fn new_path(
        segment_count: usize,
        maximum_open_handles: Option<usize>,
        statistics: Arc<ReaderStatisticsCollector>,
    ) -> Result<Self> {
        validate_maximum_open_handles(maximum_open_handles)?;
        Ok(Self {
            files: (0..segment_count).map(|_| None).collect(),
            lengths: vec![None; segment_count],
            ever_opened: vec![false; segment_count],
            open_order: VecDeque::new(),
            maximum_open_handles,
            mode: SegmentFilePoolMode::ReopenFromPath,
            statistics,
        })
    }

    fn new_readers(
        readers: Vec<SuppliedSegmentReader>,
        maximum_open_handles: Option<usize>,
        statistics: Arc<ReaderStatisticsCollector>,
    ) -> Result<Self> {
        validate_maximum_open_handles(maximum_open_handles)?;
        let segment_count = readers.len();
        if maximum_open_handles.is_some_and(|maximum| maximum < segment_count) {
            return Err(EwfError::Unsupported(
                "maximum open handles cannot evict supplied segment readers".into(),
            ));
        }

        statistics.record_segment_handle_open(segment_count);
        Ok(Self {
            files: readers
                .into_iter()
                .map(|reader| Some(SegmentFileHandle::Supplied(reader)))
                .collect(),
            lengths: vec![None; segment_count],
            ever_opened: vec![true; segment_count],
            open_order: (0..segment_count).collect(),
            maximum_open_handles,
            mode: SegmentFilePoolMode::SuppliedReaders,
            statistics,
        })
    }

    fn maximum_open_handles(&self) -> Option<usize> {
        self.maximum_open_handles
    }

    fn segment_len(&mut self, segment_index: usize, path: &Path) -> Result<u64> {
        if let Some(length) = self
            .lengths
            .get(segment_index)
            .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?
        {
            return Ok(*length);
        }

        let length = self
            .file_mut(segment_index, path)?
            .as_reader_mut()
            .segment_len()?;
        let cached = self
            .lengths
            .get_mut(segment_index)
            .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
        *cached = Some(length);
        Ok(length)
    }

    fn set_maximum_open_handles(&mut self, maximum_open_handles: Option<usize>) -> Result<()> {
        validate_maximum_open_handles(maximum_open_handles)?;
        if !self.can_close_handles()
            && maximum_open_handles.is_some_and(|maximum| maximum < self.open_count())
        {
            return Err(EwfError::Unsupported(
                "maximum open handles cannot evict supplied segment readers".into(),
            ));
        }
        let previous_maximum_open_handles = self.maximum_open_handles;
        self.maximum_open_handles = maximum_open_handles;
        if let Err(err) = self.enforce_limit() {
            self.maximum_open_handles = previous_maximum_open_handles;
            return Err(err);
        }
        Ok(())
    }

    fn open_count(&self) -> usize {
        self.files.iter().filter(|file| file.is_some()).count()
    }

    fn reserve_handle(&mut self) -> Result<()> {
        if let Some(maximum_open_handles) = self.maximum_open_handles {
            if self.open_count() >= maximum_open_handles && !self.can_close_handles() {
                return Err(EwfError::Unsupported(
                    "maximum open handles cannot evict supplied segment readers".into(),
                ));
            }
            while self.open_count() >= maximum_open_handles {
                if !self.close_least_recently_used()? {
                    return Err(EwfError::Unsupported(
                        "maximum open handles are all serving active reads".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn file_mut(&mut self, segment_index: usize, path: &Path) -> Result<&mut SegmentFileHandle> {
        let slot = self
            .files
            .get(segment_index)
            .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
        if slot.is_none() {
            self.reserve_handle()?;
            let was_opened = *self
                .ever_opened
                .get(segment_index)
                .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
            let file = match self.mode {
                SegmentFilePoolMode::ReopenFromPath => {
                    Some(SegmentFileHandle::Path(PathSegmentReader {
                        file: Arc::new(File::open(path)?),
                        position: 0,
                    }))
                }
                SegmentFilePoolMode::SuppliedReaders => None,
            }
            .ok_or_else(|| {
                EwfError::Malformed("supplied segment reader was unexpectedly closed".into())
            })?;
            let slot = self
                .files
                .get_mut(segment_index)
                .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
            *slot = Some(file);
            self.ever_opened[segment_index] = true;
            if was_opened {
                self.statistics.record_segment_handle_reopen();
            } else {
                self.statistics.record_segment_handle_open(1);
            }
        }
        self.mark_used(segment_index);
        self.files[segment_index]
            .as_mut()
            .ok_or_else(|| EwfError::Malformed("segment file was not opened".into()))
    }

    fn acquire_path_file(
        &mut self,
        segment_index: usize,
        path: &Path,
    ) -> Result<Option<Arc<File>>> {
        if self.mode != SegmentFilePoolMode::ReopenFromPath {
            return Err(EwfError::Malformed(
                "positioned file requested for a supplied segment reader".into(),
            ));
        }
        let slot = self
            .files
            .get(segment_index)
            .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
        if slot.is_none() {
            if let Some(maximum_open_handles) = self.maximum_open_handles {
                while self.open_count() >= maximum_open_handles {
                    if !self.close_least_recently_used()? {
                        return Ok(None);
                    }
                }
            }
            let was_opened = *self
                .ever_opened
                .get(segment_index)
                .ok_or_else(|| EwfError::Malformed("segment index out of range".into()))?;
            self.files[segment_index] = Some(SegmentFileHandle::Path(PathSegmentReader {
                file: Arc::new(File::open(path)?),
                position: 0,
            }));
            self.ever_opened[segment_index] = true;
            if was_opened {
                self.statistics.record_segment_handle_reopen();
            } else {
                self.statistics.record_segment_handle_open(1);
            }
        }
        self.mark_used(segment_index);
        self.files[segment_index]
            .as_ref()
            .and_then(SegmentFileHandle::path_file)
            .map(Arc::clone)
            .map(Some)
            .ok_or_else(|| EwfError::Malformed("path segment file was not opened".into()))
    }

    fn can_close_handles(&self) -> bool {
        self.mode == SegmentFilePoolMode::ReopenFromPath
    }

    fn has_supplied_readers(&self) -> bool {
        self.mode == SegmentFilePoolMode::SuppliedReaders
    }

    fn mark_used(&mut self, segment_index: usize) {
        if let Some(position) = self
            .open_order
            .iter()
            .position(|open_segment_index| *open_segment_index == segment_index)
        {
            self.open_order.remove(position);
        }
        self.open_order.push_back(segment_index);
    }

    fn enforce_limit(&mut self) -> Result<()> {
        if let Some(maximum_open_handles) = self.maximum_open_handles {
            if self.open_count() > maximum_open_handles && !self.can_close_handles() {
                return Err(EwfError::Unsupported(
                    "maximum open handles cannot evict supplied segment readers".into(),
                ));
            }
            while self.open_count() > maximum_open_handles {
                if !self.close_least_recently_used()? {
                    return Err(EwfError::Unsupported(
                        "maximum open handles are all serving active reads".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn close_least_recently_used(&mut self) -> Result<bool> {
        let candidates = self.open_order.len();
        for _ in 0..candidates {
            let Some(segment_index) = self.open_order.pop_front() else {
                break;
            };
            let Some(slot) = self.files.get_mut(segment_index) else {
                return Err(EwfError::Malformed("segment index out of range".into()));
            };
            if slot
                .as_ref()
                .is_some_and(SegmentFileHandle::idle_path_handle)
            {
                slot.take();
                return Ok(true);
            }
            if slot.is_some() {
                self.open_order.push_back(segment_index);
            }
        }
        Ok(false)
    }
}

fn validate_maximum_open_handles(maximum_open_handles: Option<usize>) -> Result<()> {
    if maximum_open_handles == Some(0) {
        return Err(EwfError::Unsupported(
            "maximum open handles must be at least one".into(),
        ));
    }
    Ok(())
}

fn data_chunk_encoding(encoding: ChunkEncoding) -> DataChunkEncoding {
    match encoding {
        ChunkEncoding::Raw => DataChunkEncoding::Raw,
        ChunkEncoding::Zlib => DataChunkEncoding::Zlib,
        ChunkEncoding::Zstd => DataChunkEncoding::Zstd,
        ChunkEncoding::Bzip2 => DataChunkEncoding::Bzip2,
        ChunkEncoding::PatternFill(pattern) => DataChunkEncoding::PatternFill(pattern),
    }
}

impl ImageCursor {
    /// Returns the current logical media byte position.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Alias for [`ImageCursor::position`].
    pub fn offset(&self) -> u64 {
        self.position()
    }

    /// Reads logical media bytes at the current cursor position and advances.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying [`Image::read_at`] call fails or the
    /// cursor position would overflow.
    pub fn read_buffer(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self.image.read_at(buf, self.position)?;
        self.position = self
            .position
            .checked_add(u64::try_from(read).expect("usize fits u64"))
            .ok_or_else(|| EwfError::Malformed("cursor position overflow".into()))?;
        Ok(read)
    }

    /// Seeks to `offset`, reads into `buf`, and advances by the bytes read.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ImageCursor::read_buffer`].
    pub fn read_buffer_at_offset(&mut self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.position = offset;
        self.read_buffer(buf)
    }

    /// Seeks the cursor using [`SeekFrom`] and returns the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek would move before the start of the image or
    /// beyond `u64` addressable space.
    pub fn seek_offset(&mut self, pos: SeekFrom) -> Result<u64> {
        self.seek_position(pos).map_err(EwfError::from)
    }

    /// Returns the segment containing the current cursor position.
    ///
    /// Positions at or beyond the logical media size return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the image chunk geometry is malformed.
    pub fn segment_filename(&self) -> Result<Option<&Path>> {
        self.image.segment_filename_for_offset(self.position)
    }

    /// Reads the data chunk at the current cursor position and advances to the next chunk.
    ///
    /// Returns `Ok(None)` when the cursor is at or beyond the logical media end.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the chunk fails or the cursor position would
    /// overflow.
    pub fn read_data_chunk(&mut self) -> Result<Option<DataChunk>> {
        let Some(chunk_index) = self.current_chunk_index()? else {
            return Ok(None);
        };
        let chunk = self.image.read_data_chunk(chunk_index)?;
        self.advance_to_chunk_end(chunk.logical_offset, chunk.logical_size)?;
        Ok(Some(chunk))
    }

    /// Reads the encoded data chunk at the current cursor position and advances.
    ///
    /// Returns `Ok(None)` when the cursor is at or beyond the logical media end.
    ///
    /// # Errors
    ///
    /// Returns an error if reading the chunk fails or the cursor position would
    /// overflow.
    pub fn read_encoded_data_chunk(&mut self) -> Result<Option<EncodedDataChunk>> {
        let Some(chunk_index) = self.current_chunk_index()? else {
            return Ok(None);
        };
        let chunk = self.image.read_encoded_data_chunk(chunk_index)?;
        self.advance_to_chunk_end(chunk.logical_offset, chunk.logical_size)?;
        Ok(Some(chunk))
    }

    fn current_chunk_index(&self) -> Result<Option<u64>> {
        if self.position >= self.image.info().logical_size {
            return Ok(None);
        }
        let chunk_size = self.image.info().chunk_size;
        if chunk_size == 0 {
            return Err(EwfError::Malformed("chunk size is zero".into()));
        }
        Ok(Some(self.position / chunk_size))
    }

    fn advance_to_chunk_end(&mut self, logical_offset: u64, logical_size: usize) -> Result<()> {
        let logical_size = u64::try_from(logical_size)
            .map_err(|_| EwfError::Malformed("chunk logical size does not fit u64".into()))?;
        self.position = logical_offset
            .checked_add(logical_size)
            .ok_or_else(|| EwfError::Malformed("cursor chunk end offset overflow".into()))?;
        Ok(())
    }

    fn seek_position(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => {
                i128::from(self.image.info().logical_size) + i128::from(offset)
            }
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of image",
            ));
        }
        self.position = u64::try_from(next).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek position does not fit u64",
            )
        })?;
        Ok(self.position)
    }
}

impl Read for ImageCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_buffer(buf).map_err(std::io::Error::other)
    }
}

impl Seek for ImageCursor {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.seek_position(pos)
    }
}

impl SingleFileCursor {
    /// Returns the current single-file byte position.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Alias for [`SingleFileCursor::position`].
    pub fn offset(&self) -> u64 {
        self.position()
    }

    /// Reads bytes at the current single-file position and advances.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying single-file read fails or the cursor
    /// position would overflow.
    pub fn read_buffer(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self
            .image
            .read_single_file_at(&self.entry, buf, self.position)?;
        self.position = self
            .position
            .checked_add(u64::try_from(read).expect("usize fits u64"))
            .ok_or_else(|| EwfError::Malformed("single file cursor position overflow".into()))?;
        Ok(read)
    }

    /// Seeks to `offset`, reads into `buf`, and advances by the bytes read.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`SingleFileCursor::read_buffer`].
    pub fn read_buffer_at_offset(&mut self, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.position = offset;
        self.read_buffer(buf)
    }

    /// Seeks the cursor using [`SeekFrom`] and returns the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the seek would move before the start of the file, the
    /// file size is unavailable, or the resulting position does not fit `u64`.
    pub fn seek_offset(&mut self, pos: SeekFrom) -> Result<u64> {
        self.seek_position(pos).map_err(EwfError::from)
    }

    fn seek_position(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let file_size = single_file_size(&self.entry).map_err(std::io::Error::other)?;
        let next = match pos {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::End(offset) => i128::from(file_size) + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        if next < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot seek before start of single file",
            ));
        }
        self.position = u64::try_from(next).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "single file cursor position does not fit u64",
            )
        })?;
        Ok(self.position)
    }
}

impl Read for SingleFileCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_buffer(buf).map_err(std::io::Error::other)
    }
}

impl Seek for SingleFileCursor {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.seek_position(pos)
    }

    fn stream_position(&mut self) -> std::io::Result<u64> {
        Ok(self.position)
    }
}

pub(crate) fn single_file_size(entry: &SingleFileEntry) -> Result<u64> {
    if let Some(size) = entry.size {
        return Ok(size);
    }

    entry.extents.iter().try_fold(0_u64, |total, extent| {
        total
            .checked_add(extent.data_size)
            .ok_or_else(|| EwfError::Malformed("single file size overflow".into()))
    })
}

struct ParsedSegment {
    format: Format,
    sections: Vec<SectionInfo>,
    format_profile: FormatProfile,
    format_profile_hint_only: bool,
    segment_number: u64,
    set_identifier: Option<[u8; 16]>,
    ewf2_header_profile: Option<Ewf2HeaderProfile>,
    ewf1_compression_method: Option<CompressionMethod>,
    ewf1_media_geometry: Option<Ewf1MediaGeometry>,
    chunk_size: u64,
    logical_size: u64,
    acquisition_complete: bool,
    media: MediaInfo,
    ranges: Vec<TableRange>,
    table_chunk_count: u64,
    metadata: EwfMetadata,
    stored_hashes: StoredHashes,
    acquisition_errors: Vec<AcquisitionError>,
    memory_extents: Vec<MemoryExtent>,
    single_files: Option<SingleFilesInfo>,
    ewf2_single_files_tables: SingleFilesAuxTables,
    ewf2_increment_data: Vec<Vec<u8>>,
    ewf2_final_information: Option<Vec<u8>>,
    ewf2_restart_data: Option<String>,
    ewf2_analytical_data: Option<String>,
    sessions: Vec<SectorRange>,
    tracks: Vec<SectorRange>,
    ewf2_device_information: Option<Vec<u8>>,
    ewf2_case_data: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct Ewf2HeaderProfile {
    major_version: u8,
    minor_version: u8,
    compression_method: ewf2::CompressionMethod,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Ewf1MediaGeometry {
    chunk_size: u64,
    logical_size: u64,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
    chunk_count: u32,
}

#[derive(Clone, Copy)]
struct Ewf1SegmentContext {
    first_chunk: u64,
    inherited_media_geometry: Option<Ewf1MediaGeometry>,
}

#[derive(Clone, Copy)]
struct Ewf1RangeProfile {
    allow_large_compressed_chunks: bool,
    compression_method: CompressionMethod,
}

#[derive(Clone)]
struct Section {
    desc: ewf1::SectionDescriptor,
    data_offset: u64,
    data_size: u64,
}

#[derive(Clone, Copy)]
struct Ewf2Section {
    desc: ewf2::SectionDescriptor,
    data_offset: u64,
    data_size: u64,
    layout: Ewf2SectionLayout,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ewf2SectionLayout {
    LeadingDescriptor,
    TrailingDescriptor,
}

fn parse_ewf1_segment(
    file: &mut dyn SegmentReader,
    segment_index: usize,
    context: Ewf1SegmentContext,
    profile_hint: FormatProfile,
    header_codepage: HeaderCodepage,
    leniency: &mut Leniency,
    statistics: &ReaderStatisticsCollector,
) -> Result<ParsedSegment> {
    let mut header = [0; ewf1::FILE_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let file_header = ewf1::FileHeader::parse(&header)?;
    let Ewf1SegmentContext {
        first_chunk,
        inherited_media_geometry,
    } = context;

    let sections = scan_ewf1_sections(file)?;
    let compression_method = detect_ewf1_compression_method(file_header, &sections)?;
    let acquisition_complete = ewf1_acquisition_complete(&sections);
    let volume = sections
        .iter()
        .find(|section| {
            matches!(
                section.desc.section_type.as_str(),
                "volume" | "disk" | "data"
            )
        })
        .map(|section| {
            let data = read_exact_at(file, section.data_offset, section.data_size)?;
            validate_present_ewf1_media_checksum(&data, &section.desc.section_type)?;
            ewf1::Volume::parse(&data)
        })
        .transpose()?;
    if segment_index == 0 && volume.is_none() {
        return Err(EwfError::Malformed("missing EWF1 media section".into()));
    }
    let (chunk_size, logical_size, smart_profile, media) = if let Some(volume) = volume.as_ref() {
        let chunk_size = volume.chunk_size()?;
        validate_chunk_size(chunk_size)?;
        let declared_logical_size = volume.logical_size()?;
        let logical_size = if declared_logical_size > 0 {
            declared_logical_size
        } else {
            chunk_size
                .checked_mul(u64::from(volume.chunk_count))
                .ok_or_else(|| EwfError::Malformed("EWF1 logical size overflow".into()))?
        };
        let smart_profile = !file_header.logical && volume.smart;
        let media = MediaInfo {
            sectors_per_chunk: Some(u64::from(volume.sectors_per_chunk)),
            bytes_per_sector: Some(u64::from(volume.bytes_per_sector)),
            sector_count: Some(volume.sector_count),
            chunk_count: Some(u64::from(volume.chunk_count)),
            error_granularity: volume.error_granularity.map(u64::from),
            set_identifier: volume.set_identifier,
            ewf2_segment_file_version: None,
            compression_method: Some(compression_method),
            compression_values: CompressionValues {
                level: volume
                    .compression_level
                    .map(|value| CompressionLevel::from_i8(value as i8))
                    .unwrap_or_default(),
                ..CompressionValues::default()
            },
            media_type: volume
                .media_type
                .map(ewf1_media_type)
                .or_else(|| smart_profile.then_some(MediaType::Removable)),
            media_flags: ewf1_media_flags(volume.media_flags, file_header.logical || smart_profile),
        };
        (chunk_size, logical_size, smart_profile, media)
    } else {
        (0, 0, false, MediaInfo::default())
    };
    let ewf1_media_geometry = volume.as_ref().map(|volume| Ewf1MediaGeometry {
        chunk_size,
        logical_size,
        sectors_per_chunk: volume.sectors_per_chunk,
        bytes_per_sector: volume.bytes_per_sector,
        sector_count: volume.sector_count,
        chunk_count: volume.chunk_count,
    });

    let mut metadata = EwfMetadata::default();
    let mut stored_hashes = StoredHashes::default();
    let mut acquisition_errors = Vec::new();
    let memory_extents = Vec::new();
    let mut single_files = None;
    let mut format_profile = if file_header.logical {
        FormatProfile::LogicalEnCase5
    } else if smart_profile {
        FormatProfile::Smart
    } else if volume.is_none() {
        FormatProfile::Unknown
    } else if profile_hint != FormatProfile::Unknown {
        profile_hint
    } else {
        FormatProfile::EnCase5
    };
    let mut format_profile_hint_only = !file_header.logical && !smart_profile;
    let mut format_profile_detected_from_header2 = false;
    let mut sessions = Vec::new();
    let mut tracks = Vec::new();
    for section in &sections {
        let section_type = section.desc.section_type.as_str();
        if !matches!(
            section_type,
            "header"
                | "header2"
                | "xheader"
                | "error2"
                | "session"
                | "hash"
                | "digest"
                | "xhash"
                | "ltree"
        ) {
            continue;
        }
        // Fixed-size sections are checked before reading so that a damaged size
        // never causes a large allocation.
        let expected_size = match section_type {
            "hash" => Some((EWF1_HASH_SECTION_SIZE, "EWF1 MD5")),
            "digest" => Some((EWF1_DIGEST_SECTION_SIZE, "EWF1 digest")),
            _ => None,
        };
        if let Some((expected, label)) = expected_size
            && let Err(error) = validate_hash_section_size(section.data_size, expected, label)
        {
            leniency.tolerate(
                error,
                DefectKind::MetadataUnavailable,
                segment_index,
                section.desc.offset,
                &format!("the {section_type} section's values are not used"),
            )?;
            continue;
        }
        let data = read_exact_at(file, section.data_offset, section.data_size)?;
        let parsed = parse_ewf1_metadata_section(
            section_type,
            &data,
            compression_method,
            header_codepage,
            leniency.is_lenient(),
            &mut Ewf1MetadataTargets {
                metadata: &mut metadata,
                stored_hashes: &mut stored_hashes,
                acquisition_errors: &mut acquisition_errors,
                single_files: &mut single_files,
                sessions: &mut sessions,
                tracks: &mut tracks,
                format_profile: &mut format_profile,
                format_profile_hint_only: &mut format_profile_hint_only,
                format_profile_detected_from_header2: &mut format_profile_detected_from_header2,
            },
            volume
                .as_ref()
                .map(|volume| volume.sector_count)
                .or_else(|| inherited_media_geometry.map(|geometry| geometry.sector_count)),
        );
        match parsed {
            Ok(()) => {}
            Err(MetadataError::Damaged(error)) => leniency.tolerate(
                error,
                DefectKind::MetadataUnavailable,
                segment_index,
                section.desc.offset,
                &format!("the {section_type} section's values are not used"),
            )?,
            Err(MetadataError::Fatal(error)) => return Err(error),
        }
    }

    let ranges = parse_ewf1_ranges(
        file,
        &sections,
        segment_index,
        first_chunk,
        logical_size,
        Ewf1RangeProfile {
            allow_large_compressed_chunks: volume.as_ref().is_some_and(|volume| volume.smart),
            compression_method,
        },
        statistics,
    )?;
    let table_chunk_count = ranges.iter().try_fold(0_u64, |count, range| {
        count
            .checked_add(range.chunk_count)
            .ok_or_else(|| EwfError::Malformed("EWF1 table chunk count overflow".into()))
    })?;
    Ok(ParsedSegment {
        format: Format::Ewf1,
        sections: sections
            .iter()
            .map(|section| SectionInfo {
                segment_index,
                kind: SectionKind::Ewf1(section.desc.section_type.clone()),
                descriptor_offset: section.desc.offset,
                data_offset: section.data_offset,
                data_size: section.data_size,
                linked_descriptor_offset: section.desc.next,
                data_flags: 0,
            })
            .collect(),
        format_profile,
        format_profile_hint_only,
        segment_number: u64::from(file_header.segment_number),
        set_identifier: volume.as_ref().and_then(|volume| volume.set_identifier),
        ewf2_header_profile: None,
        ewf1_compression_method: Some(compression_method),
        ewf1_media_geometry,
        chunk_size,
        logical_size,
        acquisition_complete,
        media,
        ranges,
        table_chunk_count,
        metadata,
        stored_hashes,
        acquisition_errors,
        memory_extents,
        single_files,
        ewf2_single_files_tables: SingleFilesAuxTables::default(),
        ewf2_increment_data: Vec::new(),
        ewf2_final_information: None,
        ewf2_restart_data: None,
        ewf2_analytical_data: None,
        sessions,
        tracks,
        ewf2_device_information: None,
        ewf2_case_data: None,
    })
}

/// Destinations for values parsed from EWF1 metadata sections.
struct Ewf1MetadataTargets<'a> {
    metadata: &'a mut EwfMetadata,
    stored_hashes: &'a mut StoredHashes,
    acquisition_errors: &'a mut Vec<AcquisitionError>,
    single_files: &'a mut Option<SingleFilesInfo>,
    sessions: &'a mut Vec<SectorRange>,
    tracks: &'a mut Vec<SectorRange>,
    format_profile: &'a mut FormatProfile,
    format_profile_hint_only: &'a mut bool,
    format_profile_detected_from_header2: &'a mut bool,
}

/// Separates damage that lenient opening may skip from errors that always
/// fail opening, such as I/O errors and intact but conflicting hash references.
enum MetadataError {
    Damaged(EwfError),
    Fatal(EwfError),
}

impl From<EwfError> for MetadataError {
    fn from(error: EwfError) -> Self {
        Self::Fatal(error)
    }
}

fn damaged(error: EwfError) -> MetadataError {
    match error {
        EwfError::Malformed(_) | EwfError::BufferTooShort { .. } => MetadataError::Damaged(error),
        other => MetadataError::Fatal(other),
    }
}

/// Parses one EWF1 metadata section. Values are written to `targets` only once
/// the whole section has parsed, so a damaged section contributes nothing.
fn parse_ewf1_metadata_section(
    section_type: &str,
    data: &[u8],
    compression_method: CompressionMethod,
    header_codepage: HeaderCodepage,
    lenient: bool,
    targets: &mut Ewf1MetadataTargets<'_>,
    sector_count: Option<u64>,
) -> std::result::Result<(), MetadataError> {
    let zstd_payload = compression_method == CompressionMethod::Zstd
        && data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let payload = || -> std::result::Result<Vec<u8>, MetadataError> {
        if lenient && !zstd_payload && zlib_payload_is_damaged(data) {
            return Err(MetadataError::Damaged(EwfError::Malformed(format!(
                "EWF1 {section_type} section is compressed but does not decompress"
            ))));
        }
        Ok(ewf1_metadata_payload(data, compression_method)?)
    };
    match section_type {
        "header" => {
            let payload = payload()?;
            let text = decode_header_bytes(&payload, header_codepage);
            if !*targets.format_profile_detected_from_header2
                && apply_detected_ewf1_format_profile(
                    targets.format_profile,
                    detect_ewf1_header_profile(&text, 1),
                )
            {
                *targets.format_profile_hint_only = false;
            }
            parse_header_data(&payload, header_codepage, targets.metadata);
        }
        "header2" => {
            let payload = payload()?;
            if apply_detected_ewf1_format_profile(
                targets.format_profile,
                detect_ewf1_header2_profile(&payload),
            ) {
                *targets.format_profile_hint_only = false;
                *targets.format_profile_detected_from_header2 = true;
            }
            parse_header2_data(&payload, targets.metadata);
        }
        "xheader" => parse_xheader_data(&payload()?, targets.metadata),
        "error2" => targets
            .acquisition_errors
            .extend(parse_error2_data(data).map_err(damaged)?),
        "session" => {
            let sector_count = sector_count.ok_or_else(|| {
                MetadataError::Damaged(EwfError::Malformed(
                    "EWF1 session section has no media geometry to inherit".into(),
                ))
            })?;
            let parsed_sessions = parse_session_data(data, 1, sector_count).map_err(damaged)?;
            targets.sessions.extend(parsed_sessions.sessions);
            targets.tracks.extend(parsed_sessions.tracks);
        }
        "hash" => {
            validate_adler32_checksum(data, 32, 32, "EWF1 MD5 hash").map_err(damaged)?;
            if let Some(hash) = parse_nonzero_hash::<16>(data) {
                insert_hash_value(targets.stored_hashes, "MD5", &hash)?;
            }
        }
        "digest" => {
            validate_adler32_checksum(data, 76, 76, "EWF1 digest").map_err(damaged)?;
            if let Some(hash) = parse_nonzero_hash::<16>(&data[..16]) {
                insert_hash_value(targets.stored_hashes, "MD5", &hash)?;
            }
            if let Some(hash) = parse_nonzero_hash::<20>(&data[16..36]) {
                insert_hash_value(targets.stored_hashes, "SHA1", &hash)?;
            }
        }
        "xhash" => {
            // Malformed or conflicting values in an intact section still fail.
            let mut parsed = targets.stored_hashes.clone();
            parse_xhash_data(&payload()?, &mut parsed)?;
            *targets.stored_hashes = parsed;
        }
        "ltree" => merge_single_files(
            targets.single_files,
            Some(parse_ewf1_ltree_data(data).map_err(damaged)?),
        )?,
        _ => {}
    }
    Ok(())
}

/// True when `data` starts like a zlib stream but does not decompress, which is
/// how damage to a compressed metadata section shows.
fn zlib_payload_is_damaged(data: &[u8]) -> bool {
    let [cmf, flg, ..] = *data else {
        return false;
    };
    let looks_like_zlib = cmf & 0x0f == 8 && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0;
    if !looks_like_zlib {
        return false;
    }
    let mut decompressed = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .take(MAX_DECOMPRESSED_METADATA + 1)
        .read_to_end(&mut decompressed)
        .is_err()
}

fn ewf1_media_type(value: u8) -> MediaType {
    match value {
        0x00 => MediaType::Removable,
        0x01 => MediaType::Fixed,
        0x03 => MediaType::Optical,
        0x0e => MediaType::SingleFiles,
        0x10 => MediaType::Memory,
        value => MediaType::Unknown(value),
    }
}

fn ewf1_media_flags(value: Option<u8>, logical_file_header: bool) -> MediaFlags {
    value.map_or(
        MediaFlags {
            physical: !logical_file_header,
            fastbloc: false,
            tableau: false,
        },
        |value| MediaFlags {
            physical: value & 0x02 != 0,
            fastbloc: value & 0x04 != 0,
            tableau: value & 0x08 != 0,
        },
    )
}

fn detect_ewf1_compression_method(
    file_header: ewf1::FileHeader,
    sections: &[Section],
) -> Result<CompressionMethod> {
    let header_method = match file_header.format_marker {
        0x01 | 0x81 => CompressionMethod::Zlib,
        0x21 | 0xa1 => CompressionMethod::Zstd,
        marker => {
            return Err(EwfError::Malformed(format!(
                "unsupported EWF1 file header marker 0x{marker:02x}"
            )));
        }
    };

    let mut descriptor_method = None;
    for marker in sections
        .iter()
        .filter(|section| section.desc.section_type == "header")
        .filter_map(|section| section.desc.compression_method.as_deref())
    {
        let observed = if marker.eq_ignore_ascii_case("zstd") {
            CompressionMethod::Zstd
        } else if marker.eq_ignore_ascii_case("zlib") || marker.eq_ignore_ascii_case("deflate") {
            CompressionMethod::Zlib
        } else {
            return Err(EwfError::Malformed(format!(
                "unsupported EWF1 descriptor compression marker {marker:?}"
            )));
        };
        if descriptor_method.is_some_and(|expected| expected != observed) {
            return Err(EwfError::Malformed(
                "EWF1 descriptor compression marker conflict".into(),
            ));
        }
        descriptor_method.get_or_insert(observed);
    }

    if descriptor_method.is_some_and(|observed| observed != header_method) {
        return Err(EwfError::Malformed(
            "EWF1 file header and descriptor compression marker conflict".into(),
        ));
    }
    Ok(header_method)
}

fn ewf1_format_profile_hint_from_path(path: &Path) -> FormatProfile {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.starts_with('e') => FormatProfile::Ewf,
        Some(extension) if extension.starts_with('E') => FormatProfile::EnCase2,
        Some(extension) if extension.starts_with('L') => FormatProfile::LogicalEnCase5,
        Some(extension) if extension.starts_with('s') || extension.starts_with('S') => {
            FormatProfile::Smart
        }
        _ => FormatProfile::Unknown,
    }
}

fn parse_segment(
    file: &mut dyn SegmentReader,
    first_path: &Path,
    segment_index: usize,
    ewf1_context: Ewf1SegmentContext,
    leniency: &mut Leniency,
    header_codepage: HeaderCodepage,
    statistics: &ReaderStatisticsCollector,
) -> Result<ParsedSegment> {
    let mut signature = [0; 8];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut signature)?;
    if signature == ewf1::EVF_SIGNATURE || signature == ewf1::LVF_SIGNATURE {
        parse_ewf1_segment(
            file,
            segment_index,
            ewf1_context,
            // Extensions advance EZZ -> FAA (and can eventually reach Sxx).
            // Family hints belong to the first segment, never the continuation
            // name. Explicit metadata in each segment is still checked below.
            ewf1_format_profile_hint_from_path(first_path),
            header_codepage,
            leniency,
            statistics,
        )
    } else if signature == ewf2::EX01_SIGNATURE || signature == ewf2::LEF2_SIGNATURE {
        parse_ewf2_segment(file, segment_index, leniency, statistics)
    } else {
        Err(EwfError::InvalidSignature)
    }
}

fn parse_ewf2_segment(
    file: &mut dyn SegmentReader,
    segment_index: usize,
    leniency: &mut Leniency,
    statistics: &ReaderStatisticsCollector,
) -> Result<ParsedSegment> {
    let strictness = if leniency.is_lenient() {
        OpenStrictness::Lenient
    } else {
        OpenStrictness::Strict
    };
    let mut header = [0; ewf2::FILE_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let header = ewf2::FileHeader::parse(&header)?;
    let sections = scan_ewf2_sections(file, strictness)?;
    let acquisition_complete = ewf2_acquisition_complete(&sections);

    let mut chunk_size = 0;
    let mut logical_size = 0;
    let mut metadata = EwfMetadata::default();
    let mut stored_hashes = StoredHashes::default();
    let mut acquisition_errors = Vec::new();
    let mut memory_extents = Vec::new();
    let mut single_files = None;
    let mut ewf2_single_files_tables = SingleFilesAuxTables::default();
    let mut ewf2_increment_data = Vec::new();
    let mut ewf2_final_information = None;
    let mut ewf2_restart_data = None;
    let mut ewf2_analytical_data = None;
    let mut session_table_data = Vec::new();
    let mut sessions = Vec::new();
    let mut tracks = Vec::new();
    let mut media = MediaInfo {
        sectors_per_chunk: None,
        bytes_per_sector: None,
        sector_count: None,
        chunk_count: None,
        error_granularity: None,
        set_identifier: Some(header.set_identifier),
        ewf2_segment_file_version: Some(SegmentFileVersion {
            major: header.major_version,
            minor: header.minor_version,
        }),
        compression_method: Some(public_compression_method(header.compression_method)),
        compression_values: CompressionValues::default(),
        media_type: None,
        media_flags: MediaFlags {
            physical: !header.logical,
            fastbloc: false,
            tableau: false,
        },
    };
    let mut device_information = None;
    let mut case_data = None;
    for section in &sections {
        if let ewf2::SectionType::Unknown(value) = section.desc.section_type {
            // Strict opening rejects unknown types while scanning the chain.
            leniency.record(
                DefectKind::Irregular,
                Some(segment_index),
                Some(section.desc.offset),
                format!("skipped unknown EWF2 section type 0x{value:x}"),
            );
            continue;
        }
        // Each arm validates the section before storing any of its values, so a
        // damaged section that lenient opening skips contributes nothing.
        let result = (|| -> std::result::Result<(), MetadataError> {
            match section.desc.section_type {
                ewf2::SectionType::DeviceInformation => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let data =
                        ewf2_metadata_payload(&data, header.compression_method).map_err(damaged)?;
                    let geometry = parse_ewf2_device_info(&data).map_err(damaged)?;
                    remember_ewf2_metadata_payload(
                        &mut device_information,
                        &data,
                        "device information",
                    )?;
                    parse_ewf2_device_info_values(&data, &mut metadata);
                    if let Some(size) = geometry.chunk_size {
                        chunk_size = size;
                    }
                    if let Some(size) = geometry.logical_size {
                        logical_size = size;
                    }
                    apply_ewf2_geometry(&mut media, geometry);
                }
                ewf2::SectionType::CaseData => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let data =
                        ewf2_metadata_payload(&data, header.compression_method).map_err(damaged)?;
                    let geometry = parse_ewf2_device_info(&data).map_err(damaged)?;
                    remember_ewf2_metadata_payload(&mut case_data, &data, "case data")?;
                    parse_ewf2_case_data(&data, &mut metadata);
                    if chunk_size == 0
                        && let Some(size) = geometry.chunk_size
                    {
                        chunk_size = size;
                    }
                    if logical_size == 0
                        && let Some(size) = geometry.logical_size
                    {
                        logical_size = size;
                    }
                    apply_ewf2_geometry_if_missing(&mut media, geometry);
                }
                ewf2::SectionType::Md5Hash => {
                    validate_hash_section_size(
                        section.data_size,
                        EWF2_HASH_SECTION_SIZE,
                        "EWF2 MD5",
                    )
                    .map_err(damaged)?;
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    validate_adler32_checksum(&data, 16, 16, "EWF2 MD5 hash").map_err(damaged)?;
                    if let Some(hash) = parse_nonzero_hash::<16>(&data) {
                        insert_hash_value(&mut stored_hashes, "MD5", &hash)?;
                    }
                }
                ewf2::SectionType::Sha1Hash => {
                    validate_hash_section_size(
                        section.data_size,
                        EWF2_HASH_SECTION_SIZE,
                        "EWF2 SHA1",
                    )
                    .map_err(damaged)?;
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    validate_adler32_checksum(&data, 20, 20, "EWF2 SHA1 hash").map_err(damaged)?;
                    if let Some(hash) = parse_nonzero_hash::<20>(&data) {
                        insert_hash_value(&mut stored_hashes, "SHA1", &hash)?;
                    }
                }
                ewf2::SectionType::ErrorTable => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    acquisition_errors.extend(parse_ewf2_error_table_data(&data).map_err(damaged)?);
                }
                ewf2::SectionType::MemoryExtentsTable => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    memory_extents.extend(parse_ewf2_memory_extents_table(&data).map_err(damaged)?);
                }
                ewf2::SectionType::SingleFilesData => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let parsed = parse_ewf2_single_files_data(&data).map_err(damaged)?;
                    merge_single_files(&mut single_files, Some(parsed))?;
                }
                ewf2::SectionType::SingleFilesTable => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let parsed = parse_ewf2_single_files_aux_u64_table(
                        &data,
                        "EWF2 single files 0x21 table",
                    )
                    .map_err(damaged)?;
                    merge_single_files_aux_u64_table(
                        &mut ewf2_single_files_tables.table_0x21_entries,
                        parsed,
                        "0x21",
                    )?;
                }
                ewf2::SectionType::SingleFilesMd5HashTable => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let parsed = parse_ewf2_single_files_md5_hash_table(&data).map_err(damaged)?;
                    merge_single_files_aux_md5_table(
                        &mut ewf2_single_files_tables.md5_hashes,
                        parsed,
                    )?;
                }
                ewf2::SectionType::SingleFilesUnknownTable => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    let parsed = parse_ewf2_single_files_aux_u64_table(
                        &data,
                        "EWF2 single files 0x23 table",
                    )
                    .map_err(damaged)?;
                    merge_single_files_aux_u64_table(
                        &mut ewf2_single_files_tables.table_0x23_entries,
                        parsed,
                        "0x23",
                    )?;
                }
                ewf2::SectionType::IncrementData => {
                    ewf2_increment_data.push(read_exact_at(
                        file,
                        section.data_offset,
                        section.data_size,
                    )?);
                }
                ewf2::SectionType::FinalInformation => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    merge_optional_ewf2_raw_section(
                        &mut ewf2_final_information,
                        Some(data),
                        "final information",
                    )?;
                }
                ewf2::SectionType::RestartData => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    ewf2_restart_data = Some(
                        decode_ewf2_string_section(
                            &data,
                            header.compression_method,
                            "restart data",
                        )
                        .map_err(damaged)?,
                    );
                }
                ewf2::SectionType::AnalyticalData => {
                    let data = read_exact_at(file, section.data_offset, section.data_size)?;
                    ewf2_analytical_data = Some(
                        decode_ewf2_string_section(
                            &data,
                            header.compression_method,
                            "analytical data",
                        )
                        .map_err(damaged)?,
                    );
                }
                ewf2::SectionType::SessionTable => {
                    session_table_data.push((
                        section.desc.offset,
                        read_exact_at(file, section.data_offset, section.data_size)?,
                    ));
                }
                _ => {}
            }
            Ok(())
        })();
        match result {
            Ok(()) => {}
            Err(MetadataError::Damaged(error)) => leniency.tolerate(
                error,
                DefectKind::MetadataUnavailable,
                segment_index,
                section.desc.offset,
                "the section's values are not used",
            )?,
            Err(MetadataError::Fatal(error)) => return Err(error),
        }
    }

    let media_sector_count = media.sector_count.unwrap_or(0);
    for (descriptor_offset, data) in session_table_data {
        match parse_session_data(&data, 2, media_sector_count) {
            Ok(parsed_sessions) => {
                sessions.extend(parsed_sessions.sessions);
                tracks.extend(parsed_sessions.tracks);
            }
            Err(error) => leniency.tolerate(
                error,
                DefectKind::MetadataUnavailable,
                segment_index,
                descriptor_offset,
                "the session table's values are not used",
            )?,
        }
    }

    if chunk_size == 0 {
        chunk_size = 32_768;
    }
    validate_chunk_size(chunk_size)?;
    let ranges = parse_ewf2_ranges(
        file,
        &sections,
        segment_index,
        logical_size,
        header.compression_method,
        statistics,
    )?;
    if logical_size == 0 {
        let discovered_chunks = ranges.iter().try_fold(0_u64, |max, range| {
            let end = range
                .first_chunk
                .checked_add(range.chunk_count)
                .ok_or_else(|| EwfError::Malformed("EWF2 table chunk count overflow".into()))?;
            Ok::<u64, EwfError>(max.max(end))
        })?;
        logical_size = chunk_size
            .checked_mul(discovered_chunks)
            .ok_or_else(|| EwfError::Malformed("EWF2 logical size overflow".into()))?;
    }
    let table_chunk_count = ranges.iter().try_fold(0_u64, |count, range| {
        count
            .checked_add(range.chunk_count)
            .ok_or_else(|| EwfError::Malformed("EWF2 table chunk count overflow".into()))
    })?;

    Ok(ParsedSegment {
        format: Format::Ewf2,
        sections: sections
            .iter()
            .map(|section| {
                let raw_kind = read_exact_at(file, section.desc.offset, 4)?;
                Ok(SectionInfo {
                    segment_index,
                    kind: SectionKind::Ewf2(u32::from_le_bytes(
                        raw_kind[..4].try_into().expect("four bytes read"),
                    )),
                    descriptor_offset: section.desc.offset,
                    data_offset: section.data_offset,
                    data_size: section.data_size,
                    linked_descriptor_offset: section.desc.previous_offset,
                    data_flags: section.desc.data_flags,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        format_profile: if header.logical {
            FormatProfile::Ewf2LogicalEnCase7
        } else {
            FormatProfile::Ewf2EnCase7
        },
        format_profile_hint_only: false,
        segment_number: u64::from(header.segment_number),
        set_identifier: Some(header.set_identifier),
        ewf2_header_profile: Some(Ewf2HeaderProfile {
            major_version: header.major_version,
            minor_version: header.minor_version,
            compression_method: header.compression_method,
        }),
        ewf1_compression_method: None,
        ewf1_media_geometry: None,
        chunk_size,
        logical_size,
        acquisition_complete,
        media,
        ranges,
        table_chunk_count,
        metadata,
        stored_hashes,
        acquisition_errors,
        memory_extents,
        single_files,
        ewf2_single_files_tables,
        ewf2_increment_data,
        ewf2_final_information,
        ewf2_restart_data,
        ewf2_analytical_data,
        sessions,
        tracks,
        ewf2_device_information: device_information,
        ewf2_case_data: case_data,
    })
}

fn scan_ewf1_sections(file: &mut dyn SegmentReader) -> Result<Vec<Section>> {
    let file_len = file.segment_len()?;
    let mut sections = Vec::new();
    let mut offset = ewf1::FILE_HEADER_SIZE as u64;
    loop {
        let descriptor_end = offset
            .checked_add(ewf1::SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| EwfError::Malformed("EWF1 section descriptor overflow".into()))?;
        if descriptor_end > file_len {
            return Err(EwfError::Malformed(
                "EWF1 section descriptor exceeds file".into(),
            ));
        }
        let mut buf = [0; ewf1::SECTION_DESCRIPTOR_SIZE];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        validate_present_adler32_checksum(&buf, 72, 72, "EWF1 section descriptor")?;
        let desc = ewf1::SectionDescriptor::parse(&buf, offset)?;
        let data_size = desc.data_size()?;
        let data_offset = descriptor_end;
        let data_end = data_offset
            .checked_add(data_size)
            .ok_or_else(|| EwfError::Malformed("EWF1 section data exceeds file".into()))?;
        if data_end > file_len {
            return Err(EwfError::Malformed("EWF1 section data exceeds file".into()));
        }
        let section_type = desc.section_type.clone();
        let next = desc.next;
        sections.push(Section {
            desc,
            data_offset,
            data_size,
        });
        if matches!(section_type.as_str(), "done" | "next") || next == 0 {
            return Ok(sections);
        }
        if next <= offset {
            return Err(EwfError::Malformed(
                "EWF1 section chain does not advance".into(),
            ));
        }
        if next < data_end {
            return Err(EwfError::Malformed(
                "EWF1 next section offset overlaps current section".into(),
            ));
        }
        offset = next;
    }
}

fn ewf1_acquisition_complete(sections: &[Section]) -> bool {
    sections
        .last()
        .is_none_or(|section| section.desc.section_type != "next")
}

fn scan_ewf2_sections(
    file: &mut dyn SegmentReader,
    strictness: OpenStrictness,
) -> Result<Vec<Ewf2Section>> {
    let file_len = file.segment_len()?;
    if file_len < ewf2::FILE_HEADER_SIZE as u64 + ewf2::SECTION_DESCRIPTOR_SIZE as u64 {
        return Err(EwfError::Malformed("EWF2 file is too short".into()));
    }

    if let Some(sections) = scan_ewf2_leading_sections(file, file_len, strictness)? {
        return Ok(sections);
    }
    scan_ewf2_trailing_sections(file, file_len, strictness)
}

fn scan_ewf2_leading_sections(
    file: &mut dyn SegmentReader,
    file_len: u64,
    strictness: OpenStrictness,
) -> Result<Option<Vec<Ewf2Section>>> {
    let mut sections = Vec::new();
    let mut offset = ewf2::FILE_HEADER_SIZE as u64;

    loop {
        if offset
            .checked_add(ewf2::SECTION_DESCRIPTOR_SIZE as u64)
            .is_none_or(|end| end > file_len)
        {
            if sections.is_empty() {
                return Ok(None);
            }
            return Err(EwfError::Malformed(
                "EWF2 leading section descriptor exceeds file".into(),
            ));
        }

        let mut buf = [0; ewf2::SECTION_DESCRIPTOR_SIZE];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        let Ok(desc) = ewf2::SectionDescriptor::parse(&buf, offset) else {
            return if sections.is_empty() {
                Ok(None)
            } else {
                Err(EwfError::Malformed(
                    "EWF2 leading section descriptor is invalid".into(),
                ))
            };
        };
        if !is_valid_ewf2_leading_descriptor(desc, strictness) {
            return if sections.is_empty() {
                Ok(None)
            } else {
                Err(EwfError::Malformed(
                    "EWF2 leading section descriptor is invalid".into(),
                ))
            };
        }
        validate_present_adler32_checksum(&buf, 60, 60, "EWF2 section descriptor")?;

        let data_offset = offset
            .checked_add(u64::from(desc.descriptor_size))
            .ok_or_else(|| EwfError::Malformed("EWF2 section data offset overflow".into()))?;
        let data_end = data_offset
            .checked_add(desc.data_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 section advance overflow".into()))?;
        if data_end > file_len {
            return if sections.is_empty() {
                Ok(None)
            } else {
                Err(EwfError::Malformed("EWF2 section data exceeds file".into()))
            };
        }
        let padding_size = ewf2_section_padding_size(desc)?;
        let next_offset = data_end
            .checked_add(padding_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 section padding overflow".into()))?;
        if next_offset > file_len {
            return Err(EwfError::Malformed(
                "EWF2 section padding exceeds file".into(),
            ));
        }
        reject_encrypted_ewf2_section(desc)?;
        validate_ewf2_section_integrity_hash(file, desc, data_offset)?;
        let section_type = desc.section_type;
        sections.push(Ewf2Section {
            desc,
            data_offset,
            data_size: desc.data_size,
            layout: Ewf2SectionLayout::LeadingDescriptor,
        });
        if is_terminal_ewf2_section(section_type) {
            return Ok(Some(sections));
        }
        if next_offset <= offset {
            return Err(EwfError::Malformed(
                "EWF2 leading section chain does not advance".into(),
            ));
        }
        offset = next_offset;
    }
}

fn scan_ewf2_trailing_sections(
    file: &mut dyn SegmentReader,
    file_len: u64,
    strictness: OpenStrictness,
) -> Result<Vec<Ewf2Section>> {
    let mut sections = Vec::new();
    let header_size = ewf2::FILE_HEADER_SIZE as u64;
    let descriptor_size = ewf2::SECTION_DESCRIPTOR_SIZE as u64;
    let mut offset = file_len
        .checked_sub(descriptor_size)
        .ok_or_else(|| EwfError::Malformed("EWF2 file is too short".into()))?;
    let max_sections = ((file_len - header_size) / descriptor_size).saturating_add(1);

    for _ in 0..max_sections {
        let mut buf = [0; ewf2::SECTION_DESCRIPTOR_SIZE];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        let desc = ewf2::SectionDescriptor::parse(&buf, offset)?;
        if !is_valid_ewf2_descriptor(desc, strictness) {
            return Err(EwfError::Malformed(
                "EWF2 trailing section descriptor is invalid".into(),
            ));
        }
        validate_present_adler32_checksum(&buf, 60, 60, "EWF2 section descriptor")?;
        ewf2_section_padding_size(desc)?;
        let data_offset = if desc.previous_offset == 0 {
            header_size
        } else {
            desc.previous_offset
                .checked_add(descriptor_size)
                .ok_or_else(|| {
                    EwfError::Malformed("EWF2 previous section offset overflow".into())
                })?
        };
        if data_offset < header_size {
            return Err(EwfError::Malformed(
                "EWF2 trailing section data precedes file header".into(),
            ));
        }
        let data_end = data_offset
            .checked_add(desc.data_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 trailing section data overflow".into()))?;
        if data_end > offset {
            return Err(EwfError::Malformed(
                "EWF2 trailing section data exceeds descriptor".into(),
            ));
        }
        if desc.previous_offset != 0 {
            if desc.previous_offset >= desc.offset {
                return Err(EwfError::Malformed(
                    "EWF2 previous section offset is not before current section".into(),
                ));
            }
            let previous_end = desc
                .previous_offset
                .checked_add(descriptor_size)
                .ok_or_else(|| {
                    EwfError::Malformed("EWF2 previous section offset overflow".into())
                })?;
            if previous_end > offset {
                return Err(EwfError::Malformed(
                    "EWF2 previous section overlaps current section descriptor".into(),
                ));
            }
        }

        reject_encrypted_ewf2_section(desc)?;
        validate_ewf2_section_integrity_hash(file, desc, data_offset)?;
        let previous_offset = desc.previous_offset;
        sections.push(Ewf2Section {
            desc,
            data_offset,
            data_size: desc.data_size,
            layout: Ewf2SectionLayout::TrailingDescriptor,
        });
        if previous_offset == 0 {
            sections.reverse();
            return Ok(sections);
        }
        offset = previous_offset;
    }

    Err(EwfError::Malformed(
        "EWF2 trailing section descriptor chain is too long".into(),
    ))
}

fn is_valid_ewf2_descriptor(desc: ewf2::SectionDescriptor, strictness: OpenStrictness) -> bool {
    desc.descriptor_size == ewf2::SECTION_DESCRIPTOR_SIZE as u32
        && (strictness == OpenStrictness::Lenient
            || !matches!(desc.section_type, ewf2::SectionType::Unknown(_)))
}

fn is_valid_ewf2_leading_descriptor(
    desc: ewf2::SectionDescriptor,
    strictness: OpenStrictness,
) -> bool {
    is_valid_ewf2_descriptor(desc, strictness)
}

fn ewf2_section_padding_size(desc: ewf2::SectionDescriptor) -> Result<u64> {
    let padding_size = u64::from(desc.padding_size);
    if padding_size > desc.data_size {
        return Err(EwfError::Malformed(
            "EWF2 section padding size exceeds data size".into(),
        ));
    }
    Ok(padding_size)
}

fn reject_encrypted_ewf2_section(desc: ewf2::SectionDescriptor) -> Result<()> {
    if desc.section_type == ewf2::SectionType::EncryptionKeys {
        return Err(EwfError::Unsupported(
            "encrypted EWF2 image with encryption keys section".into(),
        ));
    }
    if desc.encrypted {
        return Err(EwfError::Unsupported(format!(
            "encrypted EWF2 {:?} section",
            desc.section_type
        )));
    }
    Ok(())
}

fn validate_ewf2_section_integrity_hash(
    file: &mut dyn SegmentReader,
    desc: ewf2::SectionDescriptor,
    data_offset: u64,
) -> Result<()> {
    if !desc.has_integrity_hash {
        return Ok(());
    }

    let mut hasher = md5::Md5::new();
    let mut remaining = desc.data_size;
    let mut buffer = [0; 8192];
    file.seek(SeekFrom::Start(data_offset))?;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("section hash read is bounded by buffer length");
        file.read_exact(&mut buffer[..take])?;
        md5::Digest::update(&mut hasher, &buffer[..take]);
        remaining -= u64::try_from(take).expect("usize fits u64");
    }

    let calculated: [u8; 16] = hasher.finalize().into();
    if calculated != desc.data_integrity_hash {
        return Err(EwfError::Malformed(
            "EWF2 section data integrity hash mismatch".into(),
        ));
    }

    Ok(())
}

fn remember_ewf2_metadata_payload(
    target: &mut Option<Vec<u8>>,
    data: &[u8],
    label: &str,
) -> Result<()> {
    if let Some(existing) = target {
        if existing.as_slice() != data {
            return Err(EwfError::Malformed(format!("EWF2 {label} does not match")));
        }
    } else {
        *target = Some(data.to_vec());
    }
    Ok(())
}

fn is_terminal_ewf2_section(section_type: ewf2::SectionType) -> bool {
    matches!(
        section_type,
        ewf2::SectionType::Done | ewf2::SectionType::Next
    )
}

fn ewf2_acquisition_complete(sections: &[Ewf2Section]) -> bool {
    sections
        .last()
        .is_none_or(|section| section.desc.section_type != ewf2::SectionType::Next)
}

fn parse_ewf2_memory_extents_table(data: &[u8]) -> Result<Vec<MemoryExtent>> {
    const ENTRY_SIZE: usize = 16;

    if !data.len().is_multiple_of(ENTRY_SIZE) {
        return Err(EwfError::Malformed(
            "EWF2 memory extents table has partial entry".into(),
        ));
    }

    Ok(data
        .as_chunks::<ENTRY_SIZE>()
        .0
        .iter()
        .map(|entry| MemoryExtent {
            start_page: u64::from_le_bytes(entry[0..8].try_into().expect("slice length checked")),
            page_count: u64::from_le_bytes(entry[8..16].try_into().expect("slice length checked")),
        })
        .collect())
}

fn parse_ewf1_ltree_data(data: &[u8]) -> Result<SingleFilesInfo> {
    if data.len() < EWF1_LTREE_HEADER_SIZE {
        return Err(EwfError::Malformed(
            "EWF1 ltree section is too short".into(),
        ));
    }

    let single_files_data_size =
        u64::from_le_bytes(data[16..24].try_into().expect("ltree header size checked"));
    let single_files_data_size = usize::try_from(single_files_data_size)
        .map_err(|_| EwfError::Malformed("EWF1 ltree data size does not fit usize".into()))?;
    let single_files_data_end = EWF1_LTREE_HEADER_SIZE
        .checked_add(single_files_data_size)
        .ok_or_else(|| EwfError::Malformed("EWF1 ltree data size overflow".into()))?;
    if single_files_data_end > data.len() {
        return Err(EwfError::Malformed(
            "EWF1 ltree data size exceeds section".into(),
        ));
    }

    let stored = u32::from_le_bytes(data[24..28].try_into().expect("ltree header size checked"));
    let mut header = data[..EWF1_LTREE_HEADER_SIZE].to_vec();
    header[24..28].fill(0);
    validate_adler32_checksum_value(stored, &header, "EWF1 ltree header")?;

    let text = &data[EWF1_LTREE_HEADER_SIZE..single_files_data_end];
    let computed = md5::Md5::digest(text);
    if computed[..] != data[..16] {
        return Err(EwfError::Malformed("EWF1 ltree text MD5 mismatch".into()));
    }
    parse_ewf1_single_files_data(text)
}

fn parse_ewf2_single_files_aux_u64_table(data: &[u8], label: &str) -> Result<Vec<u64>> {
    parse_ewf2_single_files_aux_table(data, 8, label, |entry| {
        u64::from_le_bytes(entry.try_into().expect("entry size checked"))
    })
}

fn parse_ewf2_single_files_md5_hash_table(data: &[u8]) -> Result<Vec<[u8; 16]>> {
    parse_ewf2_single_files_aux_table(data, 16, "EWF2 single files MD5 hash table", |entry| {
        entry.try_into().expect("entry size checked")
    })
}

fn parse_ewf2_single_files_aux_table<T>(
    data: &[u8],
    entry_size: usize,
    label: &str,
    parse_entry: impl Fn(&[u8]) -> T,
) -> Result<Vec<T>> {
    const PADDED_HEADER_SIZE: usize = 32;
    const FOOTER_SIZE: usize = 4;

    if data.len() < PADDED_HEADER_SIZE + FOOTER_SIZE {
        return Err(EwfError::Malformed(format!("{label} is too short")));
    }

    validate_present_adler32_checksum(data, 16, 16, &format!("{label} header"))?;
    let entry_count = u32::from_le_bytes(data[0..4].try_into().expect("slice length checked"));
    let entry_bytes = usize::try_from(entry_count)
        .map_err(|_| EwfError::Malformed(format!("{label} entry count does not fit usize")))?
        .checked_mul(entry_size)
        .ok_or_else(|| EwfError::Malformed(format!("{label} entry bytes overflow")))?;
    let entries_offset = PADDED_HEADER_SIZE;
    let entries_end = entries_offset
        .checked_add(entry_bytes)
        .ok_or_else(|| EwfError::Malformed(format!("{label} entry range overflow")))?;
    let footer_end = entries_end
        .checked_add(FOOTER_SIZE)
        .ok_or_else(|| EwfError::Malformed(format!("{label} footer range overflow")))?;
    if footer_end > data.len() {
        return Err(EwfError::Malformed(format!(
            "{label} entries exceed section"
        )));
    }

    let stored = u32::from_le_bytes(
        data[entries_end..entries_end + FOOTER_SIZE]
            .try_into()
            .expect("footer range checked"),
    );
    if stored != 0 {
        validate_adler32_checksum_value(stored, &data[entries_offset..entries_end], label)?;
    }
    Ok(data[entries_offset..entries_end]
        .chunks_exact(entry_size)
        .map(parse_entry)
        .collect())
}

fn parse_ewf1_ranges(
    file: &mut dyn SegmentReader,
    sections: &[Section],
    segment_index: usize,
    first_chunk: u64,
    logical_size: u64,
    profile: Ewf1RangeProfile,
    statistics: &ReaderStatisticsCollector,
) -> Result<Vec<TableRange>> {
    let mut ranges = Vec::new();
    let mut next_chunk = first_chunk;
    let mut previous_table: Option<(bool, u32, u64)> = None;
    for section in sections
        .iter()
        .filter(|section| matches!(section.desc.section_type.as_str(), "table" | "table2"))
    {
        if section.data_size < 24 {
            return Err(EwfError::Malformed(
                "EWF1 table section is too short".into(),
            ));
        }
        let data = read_exact_at(file, section.data_offset, 24)?;
        validate_present_adler32_checksum(&data, 20, 20, "EWF1 table header")?;
        let entry_count = u32::from_le_bytes(data[0..4].try_into().expect("slice length checked"));
        let base_offset = u64::from_le_bytes(data[8..16].try_into().expect("slice length checked"));
        if entry_count == 0 {
            continue;
        }
        if section.desc.section_type == "table2"
            && previous_table.is_some_and(|(previous_was_table, previous_count, previous_base)| {
                previous_was_table && previous_count == entry_count && previous_base == base_offset
            })
        {
            continue;
        }

        let entry_bytes = u64::from(entry_count)
            .checked_mul(4)
            .ok_or_else(|| EwfError::Malformed("EWF1 table entry bytes overflow".into()))?;
        let entries_offset = section
            .data_offset
            .checked_add(24)
            .ok_or_else(|| EwfError::Malformed("EWF1 table entry offset overflow".into()))?;
        let entries_end = entries_offset
            .checked_add(entry_bytes)
            .ok_or_else(|| EwfError::Malformed("EWF1 table entry range overflow".into()))?;
        let section_end = section
            .data_offset
            .checked_add(section.data_size)
            .ok_or_else(|| EwfError::Malformed("EWF1 table section range overflow".into()))?;
        if entries_end > section_end {
            return Err(EwfError::Malformed(
                "EWF1 table entries exceed section".into(),
            ));
        }
        let first_entry_offset = if base_offset == 0 {
            let raw = read_exact_at(file, entries_offset, 4)?;
            Some(u64::from(
                u32::from_le_bytes(raw.try_into().expect("first table entry read size checked"))
                    & 0x7fff_ffff,
            ))
        } else {
            None
        };
        let table_resident_without_entries_checksum =
            first_entry_offset.is_some_and(|offset| offset == entries_end);
        if entries_end
            .checked_add(4)
            .is_some_and(|footer_end| footer_end <= section_end)
            && !table_resident_without_entries_checksum
        {
            validate_present_table_entries_checksum(
                file,
                entries_offset,
                entry_bytes,
                entries_end,
                "EWF1 table entries",
                statistics,
            )?;
        }

        let (data_base, data_end) = if let Some(sectors) =
            matching_sectors_section(sections, base_offset).or_else(|| {
                first_entry_offset
                    .and_then(|offset| sectors_section_containing_offset(sections, offset))
            }) {
            let data_end = sectors
                .data_offset
                .checked_add(sectors.data_size)
                .ok_or_else(|| EwfError::Malformed("EWF1 sectors range overflow".into()))?;
            (base_offset, data_end)
        } else {
            let resident_data_start = if table_resident_without_entries_checksum {
                entries_end
            } else {
                entries_end.checked_add(4).ok_or_else(|| {
                    EwfError::Malformed("EWF1 table-resident data offset overflow".into())
                })?
            };
            if resident_data_start > section_end {
                return Err(EwfError::Malformed(
                    "EWF1 table-resident data starts beyond table section".into(),
                ));
            }
            (0, section_end)
        };

        ranges.push(TableRange {
            kind: TableRangeKind::Ewf1,
            segment_index,
            first_chunk: next_chunk,
            chunk_count: u64::from(entry_count),
            entries_offset,
            base_offset: data_base,
            data_end: Some(data_end),
            ewf1_allow_large_compressed_chunks: profile.allow_large_compressed_chunks,
            ewf1_compression_method: Some(profile.compression_method),
            ewf2_compression_method: None,
        });
        next_chunk = next_chunk
            .checked_add(u64::from(entry_count))
            .ok_or_else(|| EwfError::Malformed("EWF1 table chunk count overflow".into()))?;
        previous_table = Some((
            section.desc.section_type == "table",
            entry_count,
            base_offset,
        ));
    }

    if ranges.is_empty() && logical_size > 0 {
        return Err(EwfError::Malformed("EWF1 table coverage is missing".into()));
    }
    Ok(ranges)
}

fn matching_sectors_section(sections: &[Section], base_offset: u64) -> Option<&Section> {
    sections
        .iter()
        .filter(|section| section.desc.section_type == "sectors")
        .find(|section| {
            base_offset == section.desc.offset
                || sectors_section_contains_offset(section, base_offset)
        })
}

fn sectors_section_containing_offset(sections: &[Section], offset: u64) -> Option<&Section> {
    sections
        .iter()
        .filter(|section| section.desc.section_type == "sectors")
        .find(|section| sectors_section_contains_offset(section, offset))
}

fn sectors_section_contains_offset(section: &Section, offset: u64) -> bool {
    section
        .data_offset
        .checked_add(section.data_size)
        .is_some_and(|data_end| offset >= section.data_offset && offset <= data_end)
}

fn parse_ewf2_ranges(
    file: &mut dyn SegmentReader,
    sections: &[Ewf2Section],
    segment_index: usize,
    logical_size: u64,
    compression_method: ewf2::CompressionMethod,
    statistics: &ReaderStatisticsCollector,
) -> Result<Vec<TableRange>> {
    let mut ranges = Vec::new();
    for section in sections
        .iter()
        .filter(|section| section.desc.section_type == ewf2::SectionType::SectorTable)
    {
        let minimum_table_header_size = match section.layout {
            Ewf2SectionLayout::LeadingDescriptor => ewf2::TABLE_HEADER_SIZE as u64,
            Ewf2SectionLayout::TrailingDescriptor => EWF2_TABLE_HEADER_V2_SIZE,
        };
        if section.data_size < minimum_table_header_size {
            return Err(EwfError::Malformed("EWF2 sector table is too short".into()));
        }
        let header_read_size = if section.data_size >= EWF2_TABLE_HEADER_V2_SIZE {
            EWF2_TABLE_HEADER_V2_SIZE
        } else {
            minimum_table_header_size
        };
        let data = read_exact_at(file, section.data_offset, header_read_size)?;
        validate_present_adler32_checksum(&data, 16, 16, "EWF2 table header")?;
        let header = ewf2::TableHeader::parse(&data[..ewf2::TABLE_HEADER_SIZE])?;
        let entry_count = u64::from(header.entry_count);
        if entry_count == 0 {
            continue;
        }
        let entries_bytes = entry_count
            .checked_mul(ewf2::TABLE_ENTRY_SIZE as u64)
            .ok_or_else(|| EwfError::Malformed("EWF2 table entry bytes overflow".into()))?;
        let table_header_and_padding_size = match section.layout {
            Ewf2SectionLayout::TrailingDescriptor => EWF2_TABLE_HEADER_V2_SIZE,
            Ewf2SectionLayout::LeadingDescriptor => {
                let full_header_entries_size = EWF2_TABLE_HEADER_V2_SIZE
                    .checked_add(entries_bytes)
                    .ok_or_else(|| EwfError::Malformed("EWF2 table size overflow".into()))?;
                if section.data_size >= full_header_entries_size {
                    EWF2_TABLE_HEADER_V2_SIZE
                } else {
                    ewf2::TABLE_HEADER_SIZE as u64
                }
            }
        };
        let entries_offset = section
            .data_offset
            .checked_add(table_header_and_padding_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 table entry offset overflow".into()))?;
        let entries_end = entries_offset
            .checked_add(entries_bytes)
            .ok_or_else(|| EwfError::Malformed("EWF2 table entry range overflow".into()))?;
        let section_end = section
            .data_offset
            .checked_add(section.data_size)
            .ok_or_else(|| EwfError::Malformed("EWF2 table section range overflow".into()))?;
        if entries_end > section_end {
            return Err(EwfError::Malformed(
                "EWF2 table entries exceed section".into(),
            ));
        }
        if entries_end
            .checked_add(EWF2_TABLE_FOOTER_SIZE)
            .is_some_and(|footer_end| footer_end <= section_end)
        {
            validate_present_table_entries_checksum(
                file,
                entries_offset,
                entries_bytes,
                entries_end,
                "EWF2 table entries",
                statistics,
            )?;
        }

        ranges.push(TableRange {
            kind: TableRangeKind::Ewf2,
            segment_index,
            first_chunk: header.first_chunk,
            chunk_count: entry_count,
            entries_offset,
            base_offset: 0,
            data_end: None,
            ewf1_allow_large_compressed_chunks: false,
            ewf1_compression_method: None,
            ewf2_compression_method: Some(compression_method_code(compression_method)),
        });
    }

    if ranges.is_empty() && logical_size > 0 {
        return Err(EwfError::Malformed("EWF2 image has no sector table".into()));
    }
    Ok(ranges)
}

fn read_exact_at(file: &mut dyn SegmentReader, offset: u64, size: u64) -> Result<Vec<u8>> {
    let mut data = vec![
        0;
        usize::try_from(size).map_err(|_| {
            EwfError::Malformed("read size does not fit usize".into())
        })?
    ];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(unix)]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(windows)]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(offset))?;
    file.read(buffer)
}

fn read_file_exact_at(file: &File, buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    let mut remaining = buffer;
    while !remaining.is_empty() {
        match read_file_at(file, remaining, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "segment file ended before requested range",
                ));
            }
            Ok(count) => {
                offset = offset.saturating_add(count as u64);
                remaining = &mut remaining[count..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn table_entry_offset(range: &TableRange, local_index: u64, entry_size: u64) -> Result<u64> {
    range
        .entries_offset
        .checked_add(
            local_index
                .checked_mul(entry_size)
                .ok_or_else(|| EwfError::Malformed("table entry offset overflow".into()))?,
        )
        .ok_or_else(|| EwfError::Malformed("table entry offset overflow".into()))
}

fn validate_ewf1_encoded_size(
    encoded_size: u64,
    chunk_size: u64,
    encoding: ChunkEncoding,
    allow_large_compressed_chunks: bool,
) -> Result<()> {
    if encoding == ChunkEncoding::Zlib {
        let standard_maximum = zlib_compressed_chunk_size_cap(chunk_size)?;
        if !allow_large_compressed_chunks && encoded_size <= standard_maximum {
            return validate_encoded_size(encoded_size, chunk_size, encoding);
        }
        if encoded_size == 0 {
            return Err(EwfError::Malformed("chunk data size is zero".into()));
        }
        let maximum = chunk_size
            .checked_mul(2)
            .ok_or_else(|| EwfError::Malformed("EWF1 chunk size cap overflow".into()))?;
        if encoded_size > maximum {
            return Err(EwfError::Malformed(format!(
                "EWF1 compressed chunk size {encoded_size} exceeds maximum {maximum}"
            )));
        }
        Ok(())
    } else {
        validate_encoded_size(encoded_size, chunk_size, encoding)
    }
}

fn ewf1_chunk_encoding(
    entry_compressed: bool,
    encoded_size: u64,
    chunk_size: u64,
    compression_method: CompressionMethod,
) -> Result<ChunkEncoding> {
    if entry_compressed {
        return match compression_method {
            CompressionMethod::Zlib => Ok(ChunkEncoding::Zlib),
            CompressionMethod::Zstd => Ok(ChunkEncoding::Zstd),
            method => Err(EwfError::Unsupported(format!(
                "unsupported EWF1 compression method {method:?}"
            ))),
        };
    }
    if compression_method == CompressionMethod::Zlib
        && encoded_size > raw_chunk_size_cap(chunk_size)?
        && encoded_size <= zlib_compressed_chunk_size_cap(chunk_size)?
    {
        return Ok(ChunkEncoding::Zlib);
    }
    Ok(ChunkEncoding::Raw)
}

fn decode_ewf1_entry(
    range: &TableRange,
    raw: u32,
    chunk_size: u64,
    next_raw: Option<u32>,
    is_final: bool,
) -> Result<Ewf1DecodedEntry> {
    let entry = ewf1::TableEntry::parse(&raw.to_le_bytes())?;
    let masked_offset = range
        .base_offset
        .checked_add(entry.offset)
        .ok_or_else(|| EwfError::Malformed("EWF1 chunk offset overflow".into()))?;

    if should_use_full_width_ewf1_offset(range, raw, masked_offset, chunk_size, next_raw, is_final)?
    {
        return Ok(Ewf1DecodedEntry {
            compressed: false,
            offset: range
                .base_offset
                .checked_add(u64::from(raw))
                .ok_or_else(|| EwfError::Malformed("EWF1 chunk offset overflow".into()))?,
        });
    }

    Ok(Ewf1DecodedEntry {
        compressed: entry.compressed,
        offset: masked_offset,
    })
}

fn should_use_full_width_ewf1_offset(
    range: &TableRange,
    raw: u32,
    masked_offset: u64,
    chunk_size: u64,
    next_raw: Option<u32>,
    is_final: bool,
) -> Result<bool> {
    if raw & 0x8000_0000 == 0 {
        return Ok(false);
    }
    let Some(data_end) = range.data_end else {
        return Ok(false);
    };
    let data_len = data_end
        .checked_sub(range.base_offset)
        .ok_or_else(|| EwfError::Malformed("EWF1 data region precedes base offset".into()))?;
    if data_len <= 0x8000_0000 {
        return Ok(false);
    }

    let full_offset = range
        .base_offset
        .checked_add(u64::from(raw))
        .ok_or_else(|| EwfError::Malformed("EWF1 chunk offset overflow".into()))?;
    if full_offset >= data_end {
        return Ok(false);
    }

    if let Some(next_raw) = next_raw {
        let next_masked = range
            .base_offset
            .checked_add(u64::from(next_raw & 0x7fff_ffff))
            .ok_or_else(|| EwfError::Malformed("EWF1 next chunk offset overflow".into()))?;
        let masked_is_valid = next_masked > masked_offset
            && next_masked - masked_offset <= zlib_compressed_chunk_size_cap(chunk_size)?;
        if masked_is_valid {
            return Ok(false);
        }

        let next_full = if next_raw & 0x8000_0000 != 0 {
            range
                .base_offset
                .checked_add(u64::from(next_raw))
                .ok_or_else(|| EwfError::Malformed("EWF1 next chunk offset overflow".into()))?
        } else {
            next_masked
        };
        return Ok(
            next_full > full_offset && next_full - full_offset <= raw_chunk_size_cap(chunk_size)?
        );
    }

    if is_final {
        let masked_size = data_end.saturating_sub(masked_offset);
        let full_size = data_end - full_offset;
        return Ok(masked_size > zlib_compressed_chunk_size_cap(chunk_size)?
            && full_size <= raw_chunk_size_cap(chunk_size)?);
    }

    Ok(false)
}

fn logical_chunk_size(logical_size: u64, chunk_size: u64, chunk_id: u64) -> Result<usize> {
    let logical_offset = chunk_id
        .checked_mul(chunk_size)
        .ok_or_else(|| EwfError::Malformed("logical chunk offset overflow".into()))?;
    let size = logical_size.saturating_sub(logical_offset).min(chunk_size);
    usize::try_from(size)
        .map_err(|_| EwfError::Malformed("logical chunk size does not fit usize".into()))
}

fn checksum_error_range(
    info: &ImageInfo,
    chunk_id: u64,
    logical_size: usize,
) -> Result<SectorRange> {
    let logical_offset = chunk_id
        .checked_mul(info.chunk_size)
        .ok_or_else(|| EwfError::Malformed("checksum error logical offset overflow".into()))?;
    let logical_size = u64::try_from(logical_size)
        .map_err(|_| EwfError::Malformed("checksum error size does not fit u64".into()))?;
    let Some(bytes_per_sector) = info.media.bytes_per_sector.filter(|value| *value != 0) else {
        return Ok(SectorRange {
            first_sector: logical_offset,
            sector_count: logical_size.max(1),
        });
    };

    Ok(SectorRange {
        first_sector: logical_offset / bytes_per_sector,
        sector_count: logical_size.div_ceil(bytes_per_sector).max(1),
    })
}

fn validate_chunk_size(chunk_size: u64) -> Result<()> {
    if chunk_size == 0 {
        return Err(EwfError::Malformed("chunk size is zero".into()));
    }
    if chunk_size > MAX_CHUNK_SIZE {
        return Err(EwfError::Malformed(format!(
            "chunk size {chunk_size} exceeds maximum {MAX_CHUNK_SIZE}"
        )));
    }
    Ok(())
}

fn apply_ewf2_geometry(media: &mut MediaInfo, geometry: Ewf2Geometry) {
    if let Some(value) = geometry.sectors_per_chunk {
        media.sectors_per_chunk = Some(value);
    }
    if let Some(value) = geometry.bytes_per_sector {
        media.bytes_per_sector = Some(value);
    }
    if let Some(value) = geometry.sector_count {
        media.sector_count = Some(value);
    }
    if let Some(value) = geometry.chunk_count {
        media.chunk_count = Some(value);
    }
    if let Some(value) = geometry.error_granularity {
        media.error_granularity = Some(value);
    }
    if let Some(value) = geometry.media_type {
        media.media_type = Some(value);
    }
    if let Some(value) = geometry.physical {
        media.media_flags.physical = value;
    }
    media.media_flags.fastbloc |= geometry.fastbloc;
    media.media_flags.tableau |= geometry.tableau;
}

fn apply_ewf2_geometry_if_missing(media: &mut MediaInfo, geometry: Ewf2Geometry) {
    if media.sectors_per_chunk.is_none() {
        media.sectors_per_chunk = geometry.sectors_per_chunk;
    }
    if media.bytes_per_sector.is_none() {
        media.bytes_per_sector = geometry.bytes_per_sector;
    }
    if media.sector_count.is_none() {
        media.sector_count = geometry.sector_count;
    }
    if media.chunk_count.is_none() {
        media.chunk_count = geometry.chunk_count;
    }
    if media.error_granularity.is_none() {
        media.error_granularity = geometry.error_granularity;
    }
    if media.media_type.is_none() {
        media.media_type = geometry.media_type;
    }
    if let Some(value) = geometry.physical {
        media.media_flags.physical = value;
    }
    media.media_flags.fastbloc |= geometry.fastbloc;
    media.media_flags.tableau |= geometry.tableau;
}

fn public_compression_method(method: ewf2::CompressionMethod) -> CompressionMethod {
    match method {
        ewf2::CompressionMethod::None => CompressionMethod::None,
        ewf2::CompressionMethod::Zlib => CompressionMethod::Zlib,
        ewf2::CompressionMethod::Bzip2 => CompressionMethod::Bzip2,
        ewf2::CompressionMethod::Unknown(method) => CompressionMethod::Unknown(method),
    }
}

fn compression_method_code(method: ewf2::CompressionMethod) -> u16 {
    match method {
        ewf2::CompressionMethod::None => 0,
        ewf2::CompressionMethod::Zlib => 1,
        ewf2::CompressionMethod::Bzip2 => 2,
        ewf2::CompressionMethod::Unknown(method) => method,
    }
}

fn merge_hashes(target: &mut StoredHashes, source: &StoredHashes) -> Result<()> {
    if let Some(hash) = source.md5 {
        insert_hash_value(target, "MD5", &hash)?;
    }
    if let Some(hash) = source.sha1 {
        insert_hash_value(target, "SHA1", &hash)?;
    }
    for (identifier, value) in &source.hash_values {
        crate::hashes::insert_stored_hash(target, identifier, value)?;
    }
    Ok(())
}

fn merge_segment_format_profile(
    target: &mut Option<FormatProfile>,
    target_hint_only: &mut bool,
    source: FormatProfile,
    source_hint_only: bool,
) -> Result<()> {
    if source == FormatProfile::Unknown {
        return Ok(());
    }
    match target {
        Some(existing) if *existing == FormatProfile::Unknown => {
            *existing = source;
            *target_hint_only = source_hint_only;
        }
        Some(existing) if *existing == source => {
            if !source_hint_only {
                *target_hint_only = false;
            }
        }
        Some(existing)
            if *target_hint_only
                && !source_hint_only
                && ewf1_profile_hint_matches_detected_profile(*existing, source) =>
        {
            *existing = source;
            *target_hint_only = false;
        }
        Some(existing)
            if !*target_hint_only
                && source_hint_only
                && ewf1_profile_hint_matches_detected_profile(source, *existing) => {}
        Some(existing) if *existing != source => {
            return Err(EwfError::Malformed(format!(
                "segment format profiles do not match ({existing:?} != {source:?})",
            )));
        }
        Some(_) => {}
        None => {
            *target = Some(source);
            *target_hint_only = source_hint_only;
        }
    }
    Ok(())
}

fn ewf1_profile_hint_matches_detected_profile(
    hint: FormatProfile,
    detected: FormatProfile,
) -> bool {
    matches!(
        hint,
        FormatProfile::EnCase2 | FormatProfile::EnCase5 | FormatProfile::Ewf
    ) && matches!(
        detected,
        FormatProfile::EnCase1
            | FormatProfile::EnCase2
            | FormatProfile::EnCase3
            | FormatProfile::EnCase4
            | FormatProfile::EnCase5
            | FormatProfile::EnCase6
            | FormatProfile::EnCase7
            | FormatProfile::FtkImager
            | FormatProfile::Linen5
            | FormatProfile::Linen6
            | FormatProfile::Linen7
    )
}

fn apply_detected_ewf1_format_profile(
    target: &mut FormatProfile,
    detected: Option<FormatProfile>,
) -> bool {
    let Some(detected) = detected.filter(|profile| *profile != FormatProfile::Unknown) else {
        return false;
    };
    if *target == FormatProfile::Smart && detected == FormatProfile::FtkImager {
        *target = detected;
        return true;
    }
    if matches!(
        target,
        FormatProfile::Smart
            | FormatProfile::LogicalEnCase5
            | FormatProfile::LogicalEnCase6
            | FormatProfile::LogicalEnCase7
    ) {
        return false;
    }
    *target = detected;
    true
}

fn merge_acquisition_errors(
    target: &mut Vec<AcquisitionError>,
    source: Vec<AcquisitionError>,
) -> Result<()> {
    if source.is_empty() {
        return Ok(());
    }
    target.extend(source);
    target.sort_unstable_by_key(|range| range.first_sector);
    let mut merged: Vec<AcquisitionError> = Vec::with_capacity(target.len());
    for range in target.drain(..) {
        let end = range
            .first_sector
            .checked_add(range.sector_count)
            .ok_or_else(|| EwfError::Malformed("acquisition error range overflow".into()))?;
        if let Some(previous) = merged.last_mut()
            && range.first_sector <= previous.first_sector + previous.sector_count
        {
            previous.sector_count =
                end.max(previous.first_sector + previous.sector_count) - previous.first_sector;
        } else {
            merged.push(range);
        }
    }
    *target = merged;
    Ok(())
}

fn merge_single_files(
    target: &mut Option<SingleFilesInfo>,
    source: Option<SingleFilesInfo>,
) -> Result<()> {
    if let Some(source) = source {
        if target.is_some() {
            return Err(EwfError::Malformed(
                "EWF2 image has duplicate single files data sections".into(),
            ));
        }
        *target = Some(source);
    }
    Ok(())
}

fn merge_single_files_aux_tables(
    target: &mut SingleFilesAuxTables,
    source: SingleFilesAuxTables,
) -> Result<()> {
    merge_single_files_aux_u64_table(
        &mut target.table_0x21_entries,
        source.table_0x21_entries,
        "0x21",
    )?;
    merge_single_files_aux_md5_table(&mut target.md5_hashes, source.md5_hashes)?;
    merge_single_files_aux_u64_table(
        &mut target.table_0x23_entries,
        source.table_0x23_entries,
        "0x23",
    )
}

fn merge_single_files_aux_u64_table(
    target: &mut Vec<u64>,
    source: Vec<u64>,
    table_name: &str,
) -> Result<()> {
    if source.is_empty() {
        return Ok(());
    }
    if !target.is_empty() {
        return Err(EwfError::Malformed(format!(
            "EWF2 image has duplicate single files {table_name} table sections"
        )));
    }
    *target = source;
    Ok(())
}

fn merge_single_files_aux_md5_table(
    target: &mut Vec<[u8; 16]>,
    source: Vec<[u8; 16]>,
) -> Result<()> {
    if source.is_empty() {
        return Ok(());
    }
    if !target.is_empty() {
        return Err(EwfError::Malformed(
            "EWF2 image has duplicate single files MD5 hash table sections".into(),
        ));
    }
    *target = source;
    Ok(())
}

fn merge_optional_ewf2_string_section(
    target: &mut Option<String>,
    source: Option<String>,
    label: &str,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if target.is_some() {
        return Err(EwfError::Malformed(format!(
            "EWF2 image has duplicate {label} sections"
        )));
    }
    *target = Some(source);
    Ok(())
}

fn merge_optional_ewf2_raw_section(
    target: &mut Option<Vec<u8>>,
    source: Option<Vec<u8>>,
    label: &str,
) -> Result<()> {
    let Some(source) = source else {
        return Ok(());
    };
    if target.is_some() {
        return Err(EwfError::Malformed(format!(
            "EWF2 image has duplicate {label} sections"
        )));
    }
    *target = Some(source);
    Ok(())
}

fn parse_nonzero_hash<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    let value = data.get(..N)?;
    let mut hash = [0; N];
    hash.copy_from_slice(value);
    hash.iter().any(|byte| *byte != 0).then_some(hash)
}

fn validate_adler32_checksum(
    data: &[u8],
    checksum_offset: usize,
    checksum_data_size: usize,
    label: &str,
) -> Result<()> {
    let stored = u32::from_le_bytes(
        data[checksum_offset..checksum_offset + 4]
            .try_into()
            .expect("hash section size checked"),
    );
    validate_adler32_checksum_value(stored, &data[..checksum_data_size], label)
}

fn validate_present_adler32_checksum(
    data: &[u8],
    checksum_offset: usize,
    checksum_data_size: usize,
    label: &str,
) -> Result<()> {
    let stored = u32::from_le_bytes(
        data[checksum_offset..checksum_offset + 4]
            .try_into()
            .expect("checksum offset checked"),
    );
    if stored == 0 {
        return Ok(());
    }
    validate_adler32_checksum_value(stored, &data[..checksum_data_size], label)
}

fn validate_present_table_entries_checksum(
    file: &mut dyn SegmentReader,
    entries_offset: u64,
    entry_bytes: u64,
    checksum_offset: u64,
    label: &str,
    statistics: &ReaderStatisticsCollector,
) -> Result<()> {
    let checksum = read_exact_at(file, checksum_offset, 4)?;
    let stored = u32::from_le_bytes(
        checksum
            .as_slice()
            .try_into()
            .expect("checksum size checked"),
    );
    if stored == 0 {
        return Ok(());
    }
    let started = statistics.enabled().then(Instant::now);
    let calculated = stream_adler32(file, entries_offset, entry_bytes)?;
    if let Some(started) = started {
        statistics.record_table_checksum(entry_bytes, started.elapsed());
    }
    if stored != calculated {
        return Err(EwfError::Malformed(format!("{label} checksum mismatch")));
    }
    Ok(())
}

fn stream_adler32(file: &mut dyn SegmentReader, offset: u64, size: u64) -> Result<u32> {
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining = size;
    let mut checksum = 1_u32;
    let mut buffer = vec![0_u8; TABLE_CHECKSUM_BUFFER_SIZE];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(TABLE_CHECKSUM_BUFFER_SIZE as u64))
            .expect("table checksum read is bounded by the buffer");
        file.read_exact(&mut buffer[..take])?;
        checksum = adler32_update(checksum, &buffer[..take]);
        remaining -= u64::try_from(take).expect("usize fits u64");
    }
    Ok(checksum)
}

fn validate_present_ewf1_media_checksum(data: &[u8], section_type: &str) -> Result<()> {
    let Some(checksum_offset) = data.len().checked_sub(4) else {
        return Ok(());
    };
    validate_present_adler32_checksum(
        data,
        checksum_offset,
        checksum_offset,
        &format!("EWF1 {section_type}"),
    )
}

fn validate_adler32_checksum_value(stored: u32, checksum_data: &[u8], label: &str) -> Result<()> {
    let calculated = adler32(checksum_data);
    if stored != calculated {
        return Err(EwfError::Malformed(format!("{label} checksum mismatch")));
    }
    Ok(())
}

fn validate_raw_chunk_checksum(encoded: &[u8], logical_size: usize) -> Result<()> {
    let checksum_offset = logical_size;
    if encoded.len() < checksum_offset + 4 {
        return Err(EwfError::Malformed(
            "raw chunk checksum trailer is missing".into(),
        ));
    }
    validate_adler32_checksum(encoded, checksum_offset, logical_size, "raw chunk")
}

fn adler32(data: &[u8]) -> u32 {
    adler32_update(1, data)
}

fn adler32_update(checksum: u32, data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = checksum & 0xffff;
    let mut b = checksum >> 16;
    for byte in data {
        a = (a + u32::from(*byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

fn insert_hash_value(
    stored_hashes: &mut StoredHashes,
    identifier: &str,
    hash: &[u8],
) -> Result<()> {
    crate::hashes::insert_stored_hash(stored_hashes, identifier, &hex_string(hash))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn validate_hash_section_size(observed: u64, expected: u64, label: &str) -> Result<()> {
    if observed != expected {
        return Err(EwfError::Malformed(format!(
            "{label} hash section has size {observed}, expected {expected}"
        )));
    }
    Ok(())
}

fn validate_set_identifier(
    expected: &mut Option<[u8; 16]>,
    observed: Option<[u8; 16]>,
) -> Result<()> {
    let Some(observed) = observed else {
        return Ok(());
    };
    if let Some(expected) = expected {
        if *expected != observed {
            return Err(EwfError::Malformed(
                "segment set identifier mismatch".into(),
            ));
        }
    } else {
        *expected = Some(observed);
    }
    Ok(())
}

fn validate_ewf2_header_profile(
    expected: &mut Option<Ewf2HeaderProfile>,
    observed: Option<Ewf2HeaderProfile>,
) -> Result<()> {
    let Some(observed) = observed else {
        return Ok(());
    };
    if let Some(expected) = expected {
        if expected.major_version != observed.major_version
            || expected.minor_version != observed.minor_version
        {
            return Err(EwfError::Malformed(
                "EWF2 segment file format version mismatch".into(),
            ));
        }
        if expected.compression_method != observed.compression_method {
            return Err(EwfError::Malformed(
                "EWF2 segment file compression method mismatch".into(),
            ));
        }
    } else {
        *expected = Some(observed);
    }
    Ok(())
}

fn ewf1_metadata_payload(data: &[u8], compression_method: CompressionMethod) -> Result<Vec<u8>> {
    if compression_method == CompressionMethod::Zstd && data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
    {
        let decoder = ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
            data,
            MAX_DECOMPRESSED_METADATA,
        )
        .map_err(|err| {
            EwfError::Malformed(format!(
                "EWF1 metadata Zstandard decoder initialization failed: {err}"
            ))
        })?;
        return decompress_metadata(decoder, "EWF1");
    }

    let mut decompressed = Vec::new();
    let result = flate2::read::ZlibDecoder::new(data)
        .take(MAX_DECOMPRESSED_METADATA + 1)
        .read_to_end(&mut decompressed);
    if result.is_ok() && decompressed.len() <= MAX_DECOMPRESSED_METADATA as usize {
        Ok(decompressed)
    } else {
        Ok(data.to_vec())
    }
}

fn ewf2_metadata_payload(
    data: &[u8],
    _compression_method: ewf2::CompressionMethod,
) -> Result<Vec<u8>> {
    if data.first() == Some(&0x78) {
        return decompress_metadata(flate2::read::ZlibDecoder::new(data), "EWF2");
    }
    if data.starts_with(b"BZh") {
        return decompress_metadata(bzip2::read::BzDecoder::new(data), "EWF2");
    }
    Ok(data.to_vec())
}

fn decode_ewf2_string_section(
    data: &[u8],
    compression_method: ewf2::CompressionMethod,
    label: &str,
) -> Result<String> {
    let payload = ewf2_metadata_payload(data, compression_method)?;
    if payload.len() % 2 != 0 {
        return Err(EwfError::Malformed(format!(
            "EWF2 {label} section has odd UTF-16 size"
        )));
    }

    let units: Vec<u16> = payload
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect();
    let text = String::from_utf16(&units)
        .map_err(|_| EwfError::Malformed(format!("EWF2 {label} section is not valid UTF-16LE")))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

fn decompress_metadata(reader: impl Read, format: &str) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    reader
        .take(MAX_DECOMPRESSED_METADATA + 1)
        .read_to_end(&mut decompressed)
        .map_err(|err| {
            EwfError::Malformed(format!("{format} metadata decompression failed: {err}"))
        })?;
    if decompressed.len() > MAX_DECOMPRESSED_METADATA as usize {
        return Err(EwfError::Malformed(format!(
            "{format} metadata exceeds decompressed size limit"
        )));
    }
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    use flate2::write::ZlibEncoder;

    use super::*;

    struct ObservedReader {
        cursor: Cursor<Vec<u8>>,
        maximum_read: usize,
    }

    impl Read for ObservedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.maximum_read = self.maximum_read.max(buffer.len());
            self.cursor.read(buffer)
        }
    }

    impl Seek for ObservedReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.cursor.seek(position)
        }
    }

    struct LengthObservedReader {
        cursor: Cursor<Vec<u8>>,
        seek_from_end_calls: Arc<AtomicUsize>,
    }

    impl Read for LengthObservedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buffer)
        }
    }

    impl Seek for LengthObservedReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            if matches!(position, SeekFrom::End(_)) {
                self.seek_from_end_calls
                    .fetch_add(1, AtomicOrdering::Relaxed);
            }
            self.cursor.seek(position)
        }
    }

    #[test]
    fn segment_file_pool_caches_segment_lengths() {
        let seek_from_end_calls = Arc::new(AtomicUsize::new(0));
        let reader = LengthObservedReader {
            cursor: Cursor::new(vec![0; 128]),
            seek_from_end_calls: Arc::clone(&seek_from_end_calls),
        };
        let mut pool = SegmentFilePool::new_readers(
            vec![Box::new(reader)],
            None,
            Arc::new(ReaderStatisticsCollector::new(false)),
        )
        .unwrap();
        let path = Path::new("cached-length.E01");

        assert_eq!(pool.segment_len(0, path).unwrap(), 128);
        assert_eq!(pool.segment_len(0, path).unwrap(), 128);
        assert_eq!(seek_from_end_calls.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn active_positioned_reads_preserve_the_handle_limit() {
        let first = tempfile::NamedTempFile::new().unwrap();
        let second = tempfile::NamedTempFile::new().unwrap();
        let mut pool =
            SegmentFilePool::new_path(2, Some(1), Arc::new(ReaderStatisticsCollector::new(false)))
                .unwrap();

        let active = pool.acquire_path_file(0, first.path()).unwrap().unwrap();
        assert_eq!(pool.open_count(), 1);
        assert!(pool.acquire_path_file(1, second.path()).unwrap().is_none());
        assert_eq!(pool.open_count(), 1);

        drop(active);
        assert!(pool.acquire_path_file(1, second.path()).unwrap().is_some());
        assert_eq!(pool.open_count(), 1);
    }

    #[test]
    fn table_checksum_validation_uses_bounded_reads() {
        const MAXIMUM_CHECKSUM_READ: usize = 64 * 1024;
        let entries = vec![0x5a; MAXIMUM_CHECKSUM_READ * 3 + 17];
        let mut bytes = entries.clone();
        bytes.extend_from_slice(&adler32(&entries).to_le_bytes());
        let mut reader = ObservedReader {
            cursor: Cursor::new(bytes),
            maximum_read: 0,
        };

        validate_present_table_entries_checksum(
            &mut reader,
            0,
            entries.len() as u64,
            entries.len() as u64,
            "test table",
            &ReaderStatisticsCollector::new(false),
        )
        .unwrap();

        assert!(reader.maximum_read <= MAXIMUM_CHECKSUM_READ);
    }

    #[test]
    fn table_checksum_validation_rejects_mismatch_across_multiple_reads() {
        const CHECKSUM_READ_SIZE: usize = 64 * 1024;
        let entries = vec![0x3c; CHECKSUM_READ_SIZE * 2 + 7];
        let mut bytes = entries.clone();
        bytes.extend_from_slice(&adler32(b"different").to_le_bytes());
        let mut reader = Cursor::new(bytes);

        let error = validate_present_table_entries_checksum(
            &mut reader,
            0,
            entries.len() as u64,
            entries.len() as u64,
            "test table",
            &ReaderStatisticsCollector::new(false),
        )
        .unwrap_err();

        match error {
            EwfError::Malformed(message) => {
                assert_eq!(message, "test table checksum mismatch");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn ewf1_metadata_payload_decompresses_zlib_data() {
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"metadata").unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            ewf1_metadata_payload(&compressed, CompressionMethod::Zlib).unwrap(),
            b"metadata"
        );
    }

    #[test]
    fn ewf1_metadata_payload_keeps_plain_data() {
        assert_eq!(
            ewf1_metadata_payload(b"plain metadata", CompressionMethod::Zlib).unwrap(),
            b"plain metadata"
        );
    }

    #[test]
    fn ewf2_metadata_payload_decompresses_zlib_data() {
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"metadata").unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            ewf2_metadata_payload(&compressed, ewf2::CompressionMethod::Zlib).unwrap(),
            b"metadata"
        );
    }
}

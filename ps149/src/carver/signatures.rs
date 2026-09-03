/// Magic byte signature database for forensic file carving.
/// Each entry defines header/footer byte patterns, size constraints,
/// and metadata for automated file type identification.

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FileSignature {
    pub name: &'static str,
    pub extension: &'static str,
    pub mime_type: &'static str,
    pub header: &'static [u8],
    /// Optional footer bytes to locate exact file end.
    pub footer: Option<&'static [u8]>,
    /// Maximum reasonable file size (prevents runaway carving).
    pub max_size: u64,
    /// Minimum valid file size.
    pub min_size: u64,
    /// Category for reporting.
    pub category: FileCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[allow(dead_code)]
pub enum FileCategory {
    Image,
    Document,
    Video,
    Audio,
    Archive,
    Database,
    Executable,
    Network,
    Filesystem,
    Other,
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image => write!(f, "Image"),
            Self::Document => write!(f, "Document"),
            Self::Video => write!(f, "Video"),
            Self::Audio => write!(f, "Audio"),
            Self::Archive => write!(f, "Archive"),
            Self::Database => write!(f, "Database"),
            Self::Executable => write!(f, "Executable"),
            Self::Network => write!(f, "Network"),
            Self::Filesystem => write!(f, "Filesystem"),
            Self::Other => write!(f, "Other"),
        }
    }
}

const GB: u64 = 1024 * 1024 * 1024;
const MB: u64 = 1024 * 1024;

/// Returns all known file signatures for the carving engine.
/// Ordered by forensic priority (intelligence value).
pub fn all_signatures() -> Vec<FileSignature> {
    vec![
        // ── Images ──────────────────────────────────────────────
        FileSignature {
            name: "JPEG Image",
            extension: "jpg",
            mime_type: "image/jpeg",
            header: &[0xFF, 0xD8, 0xFF],
            footer: Some(&[0xFF, 0xD9]),
            max_size: 50 * MB,
            min_size: 100,
            category: FileCategory::Image,
        },
        FileSignature {
            name: "PNG Image",
            extension: "png",
            mime_type: "image/png",
            header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            max_size: 50 * MB,
            min_size: 67,
            category: FileCategory::Image,
        },
        FileSignature {
            name: "GIF Image",
            extension: "gif",
            mime_type: "image/gif",
            header: &[0x47, 0x49, 0x46, 0x38],  // GIF8
            footer: Some(&[0x00, 0x3B]),
            max_size: 20 * MB,
            min_size: 13,
            category: FileCategory::Image,
        },
        FileSignature {
            name: "BMP Image",
            extension: "bmp",
            mime_type: "image/bmp",
            header: &[0x42, 0x4D],  // BM
            footer: None,
            max_size: 100 * MB,
            min_size: 26,
            category: FileCategory::Image,
        },
        FileSignature {
            name: "WebP Image",
            extension: "webp",
            mime_type: "image/webp",
            header: &[0x52, 0x49, 0x46, 0x46],  // RIFF (+ WEBP at offset 8)
            footer: None,
            max_size: 50 * MB,
            min_size: 12,
            category: FileCategory::Image,
        },
        FileSignature {
            name: "TIFF Image",
            extension: "tiff",
            mime_type: "image/tiff",
            header: &[0x49, 0x49, 0x2A, 0x00],  // Little-endian TIFF
            footer: None,
            max_size: 200 * MB,
            min_size: 8,
            category: FileCategory::Image,
        },

        // ── Documents ───────────────────────────────────────────
        FileSignature {
            name: "PDF Document",
            extension: "pdf",
            mime_type: "application/pdf",
            header: &[0x25, 0x50, 0x44, 0x46, 0x2D],  // %PDF-
            footer: Some(&[0x25, 0x25, 0x45, 0x4F, 0x46]),  // %%EOF
            max_size: 100 * MB,
            min_size: 67,
            category: FileCategory::Document,
        },
        FileSignature {
            name: "Microsoft Office / ZIP Archive",
            extension: "zip",
            mime_type: "application/zip",
            header: &[0x50, 0x4B, 0x03, 0x04],  // PK\x03\x04
            footer: Some(&[0x50, 0x4B, 0x05, 0x06]),  // Central directory end
            max_size: 100 * MB,
            min_size: 22,
            category: FileCategory::Archive,
        },
        FileSignature {
            name: "RTF Document",
            extension: "rtf",
            mime_type: "application/rtf",
            header: &[0x7B, 0x5C, 0x72, 0x74, 0x66],  // {\rtf
            footer: Some(&[0x7D]),  // }
            max_size: 100 * MB,
            min_size: 10,
            category: FileCategory::Document,
        },

        // ── Video ───────────────────────────────────────────────
        FileSignature {
            name: "MP4 / MOV Video",
            extension: "mp4",
            mime_type: "video/mp4",
            // ftyp atom marker (appears at offset 4 typically)
            header: &[0x66, 0x74, 0x79, 0x70],  // ftyp
            footer: None,
            max_size: 4 * GB,
            min_size: 8,
            category: FileCategory::Video,
        },
        FileSignature {
            name: "AVI Video",
            extension: "avi",
            mime_type: "video/x-msvideo",
            header: &[0x52, 0x49, 0x46, 0x46],  // RIFF (+ AVI at offset 8)
            footer: None,
            max_size: 4 * GB,
            min_size: 12,
            category: FileCategory::Video,
        },
        FileSignature {
            name: "MKV Video",
            extension: "mkv",
            mime_type: "video/x-matroska",
            header: &[0x1A, 0x45, 0xDF, 0xA3],  // EBML header
            footer: None,
            max_size: 4 * GB,
            min_size: 32,
            category: FileCategory::Video,
        },

        // ── Audio ───────────────────────────────────────────────
        FileSignature {
            name: "MP3 Audio",
            extension: "mp3",
            mime_type: "audio/mpeg",
            header: &[0x49, 0x44, 0x33],  // ID3 tag
            footer: None,
            max_size: 100 * MB,
            min_size: 128,
            category: FileCategory::Audio,
        },
        FileSignature {
            name: "WAV Audio",
            extension: "wav",
            mime_type: "audio/wav",
            header: &[0x52, 0x49, 0x46, 0x46],  // RIFF (+ WAVE at offset 8)
            footer: None,
            max_size: 2 * GB,
            min_size: 44,
            category: FileCategory::Audio,
        },
        FileSignature {
            name: "FLAC Audio",
            extension: "flac",
            mime_type: "audio/flac",
            header: &[0x66, 0x4C, 0x61, 0x43],  // fLaC
            footer: None,
            max_size: 1 * GB,
            min_size: 42,
            category: FileCategory::Audio,
        },

        // ── Database & Forensic ─────────────────────────────────
        FileSignature {
            name: "SQLite Database",
            extension: "sqlite",
            mime_type: "application/x-sqlite3",
            header: &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
                       0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00],  // "SQLite format 3\0"
            footer: None,
            max_size: 2 * GB,
            min_size: 512,
            category: FileCategory::Database,
        },

        // ── Network Captures ────────────────────────────────────
        FileSignature {
            name: "PCAP Network Capture",
            extension: "pcap",
            mime_type: "application/vnd.tcpdump.pcap",
            header: &[0xD4, 0xC3, 0xB2, 0xA1],  // Little-endian magic
            footer: None,
            max_size: 2 * GB,
            min_size: 24,
            category: FileCategory::Network,
        },
        FileSignature {
            name: "PCAP-NG Network Capture",
            extension: "pcapng",
            mime_type: "application/x-pcapng",
            header: &[0x0A, 0x0D, 0x0D, 0x0A],
            footer: None,
            max_size: 2 * GB,
            min_size: 28,
            category: FileCategory::Network,
        },

        // ── Executables ─────────────────────────────────────────
        FileSignature {
            name: "Windows PE Executable",
            extension: "exe",
            mime_type: "application/x-dosexec",
            header: &[0x4D, 0x5A],  // MZ
            footer: None,
            max_size: 500 * MB,
            min_size: 64,
            category: FileCategory::Executable,
        },
        FileSignature {
            name: "ELF Linux Executable",
            extension: "elf",
            mime_type: "application/x-elf",
            header: &[0x7F, 0x45, 0x4C, 0x46],  // \x7FELF
            footer: None,
            max_size: 500 * MB,
            min_size: 52,
            category: FileCategory::Executable,
        },

        // ── Archive ─────────────────────────────────────────────
        FileSignature {
            name: "7-Zip Archive",
            extension: "7z",
            mime_type: "application/x-7z-compressed",
            header: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],  // 7z signature
            footer: None,
            max_size: 4 * GB,
            min_size: 32,
            category: FileCategory::Archive,
        },
        FileSignature {
            name: "RAR Archive",
            extension: "rar",
            mime_type: "application/x-rar-compressed",
            header: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],  // Rar!\x1a\x07
            footer: None,
            max_size: 4 * GB,
            min_size: 20,
            category: FileCategory::Archive,
        },
        FileSignature {
            name: "GZIP Compressed",
            extension: "gz",
            mime_type: "application/gzip",
            header: &[0x1F, 0x8B, 0x08],
            footer: None,
            max_size: 2 * GB,
            min_size: 20,
            category: FileCategory::Archive,
        },
    ]
}

/// Checks if a buffer starting at a given position matches a signature header.
/// Returns the matching signature if found.
pub fn match_header<'a>(buf: &[u8], signatures: &'a [FileSignature]) -> Option<&'a FileSignature> {
    for sig in signatures {
        if buf.len() >= sig.header.len() {
            // Special case: MP4 ftyp appears at offset 4
            if sig.extension == "mp4" {
                if buf.len() >= 8 && &buf[4..8] == sig.header {
                    return Some(sig);
                }
                continue;
            }
            if &buf[..sig.header.len()] == sig.header {
                // WebP/AVI/WAV disambiguation: all start with RIFF
                if sig.header == &[0x52, 0x49, 0x46, 0x46] && buf.len() >= 12 {
                    let subtype = &buf[8..12];
                    match sig.extension {
                        "webp" if subtype != b"WEBP" => continue,
                        "avi" if subtype != b"AVI " => continue,
                        "wav" if subtype != b"WAVE" => continue,
                        _ => {}
                    }
                }
                return Some(sig);
            }
        }
    }
    None
}

/// Searches for a footer pattern in a data buffer.
/// Returns the byte offset immediately AFTER the footer (i.e., file end).
pub fn find_footer(data: &[u8], footer: &[u8]) -> Option<usize> {
    if footer.is_empty() || data.len() < footer.len() {
        return None;
    }
    // Search from the END backwards for efficiency (footers are at the end)
    for i in (0..=(data.len() - footer.len())).rev() {
        if &data[i..i + footer.len()] == footer {
            // Special handling for ZIP End of Central Directory (EOCD)
            if footer == &[0x50, 0x4B, 0x05, 0x06] {
                let eocd_fixed = i + 22;
                if data.len() >= eocd_fixed {
                    let comment_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
                    return Some((eocd_fixed + comment_len).min(data.len()));
                }
            }
            return Some(i + footer.len());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_count() {
        let sigs = all_signatures();
        assert!(sigs.len() >= 20, "Should have 20+ signatures, got {}", sigs.len());
    }

    #[test]
    fn test_jpeg_header_match() {
        let sigs = all_signatures();
        let jpeg_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let matched = match_header(&jpeg_data, &sigs);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().extension, "jpg");
    }

    #[test]
    fn test_pdf_header_match() {
        let sigs = all_signatures();
        let pdf_data = b"%PDF-1.4 some content";
        let matched = match_header(pdf_data, &sigs);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().extension, "pdf");
    }

    #[test]
    fn test_png_header_match() {
        let sigs = all_signatures();
        let png_data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        let matched = match_header(&png_data, &sigs);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().extension, "png");
    }

    #[test]
    fn test_find_jpeg_footer() {
        let data = [0x00, 0x01, 0x02, 0xFF, 0xD9, 0x00, 0x00];
        let pos = find_footer(&data, &[0xFF, 0xD9]);
        assert_eq!(pos, Some(5));
    }

    #[test]
    fn test_no_match_garbage() {
        let sigs = all_signatures();
        let garbage = [0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(match_header(&garbage, &sigs).is_none());
    }

    #[test]
    fn test_riff_disambiguation() {
        let sigs = all_signatures();
        // RIFF....WAVE should match WAV, not AVI or WebP
        let wav_data = [
            0x52, 0x49, 0x46, 0x46, // RIFF
            0x00, 0x00, 0x00, 0x00, // size
            0x57, 0x41, 0x56, 0x45, // WAVE
        ];
        let matched = match_header(&wav_data, &sigs);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().extension, "wav");
    }
}

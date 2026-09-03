/// Module 3: Advanced File Carving & Recovery Engine
///
/// Forensic-grade file recovery through signature-based carving,
/// structure parsing, and AI-assisted fragment classification.

pub mod signatures;
pub mod engine;

#[allow(unused_imports)]
pub use engine::{carve_from_source, CarvedFile, CarvingProgress, CarvingResult};
#[allow(unused_imports)]
pub use signatures::{all_signatures, FileCategory, FileSignature};

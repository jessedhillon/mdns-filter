//! Filter engine and pattern matching.

pub mod engine;
pub mod pattern;

pub use engine::FilterEngine;
pub use pattern::{CompiledPattern, PatternMatcher};

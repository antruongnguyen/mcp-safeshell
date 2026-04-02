//! The command safety pipeline.
//!
//! Stages: Parse → Classify → Guard (Location) → Gate (Permission) → Execute

pub mod parser;
pub mod classifier;
pub mod location_guard;
pub mod permission_gate;
pub mod logging;

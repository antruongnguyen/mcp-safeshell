//! The command safety pipeline.
//!
//! Stages: Parse → Classify → Guard (Location) → Gate (Permission) → Execute

pub mod classifier;
pub mod location_guard;
pub mod logging;
pub mod parser;
pub mod permission_gate;

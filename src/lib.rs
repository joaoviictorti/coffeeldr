#![doc = include_str!("../README.md")]
#![feature(c_variadic)]

mod beacon;
mod parser;
mod error;

/// Module exposing the `BeaconPack` structure for packing and manipulating binary data, strings, integers, and buffers.
pub mod beacon_pack;
/// Re-exporting everything from beacon pack
pub use beacon_pack::*;

/// Module containing the code that will load the COFF
pub mod loader;
/// Re-exporting everything from loader
pub use loader::*;
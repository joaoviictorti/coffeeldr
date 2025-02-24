#![doc = include_str!("../README.md")]
#![feature(c_variadic)]

mod beacon;
mod parser;
mod error;

/// Module exposing the `BeaconPack` structure for packing and manipulating binary data, strings, integers, and buffers.
mod beacon_pack;
pub use beacon_pack::*;

/// Module containing the code that will load the COFF
mod loader;
pub use loader::*;
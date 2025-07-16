#![no_std]
#![doc = include_str!("../README.md")]
#![allow(clippy::ptr_eq)]
#![allow(internal_features, unsafe_op_in_unsafe_fn)]
#![feature(c_variadic, core_intrinsics)]

extern crate alloc;

mod beacon;
mod error;
mod parse;
mod utils;

/// Module exposing the `BeaconPack` structure for packing and manipulating binary data, strings, integers, and buffers.
mod beacon_pack;
pub use beacon_pack::*;

/// Module containing the code that will load the COFF
mod loader;
pub use loader::*;

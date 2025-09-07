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
mod loader;
mod ffi;
mod beacon_pack;

pub use loader::*;
pub use beacon_pack::*;

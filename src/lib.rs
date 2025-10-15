#![no_std]
#![doc = include_str!("../README.md")]
#![feature(c_variadic, core_intrinsics)]
#![allow(
    clippy::ptr_eq,
    non_snake_case,
    non_camel_case_types,
    internal_features,
    unsafe_op_in_unsafe_fn
)]

extern crate alloc;

mod beacon;
mod error;
mod util;
mod loader;
mod ffi;
mod beacon_pack;

pub mod coff;

pub use loader::CoffeeLdr;
pub use beacon_pack::BeaconPack;

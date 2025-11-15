#![no_std]
#![doc = include_str!("../README.md")]
#![feature(c_variadic, core_intrinsics)]
#![allow(clippy::function_casts_as_integer)]
#![allow(clippy::ptr_eq)]
#![allow(non_snake_case, non_camel_case_types)]
#![allow(internal_features, unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod beacon;
mod error;
mod util;
mod loader;
mod beacon_pack;

pub mod coff;

pub use loader::CoffeeLdr;
pub use beacon_pack::BeaconPack;

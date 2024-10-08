#![allow(unused_imports)]

use coffeeldr::{BeaconPack, CoffeeLdr};
use hex::FromHex;

#[test]
fn test_bof_whoami() -> Result<(), Box<dyn std::error::Error>> {
    let coffee = CoffeeLdr::new("examples/whoami.x64.o")?;
    let output = coffee.run("go", None, None)?;
    println!("{output}");

    Ok(())
}

#[test]
fn test_bof_ntcreatethread() -> Result<(), Box<dyn std::error::Error>> {
    let mut pack = BeaconPack::default();

    // Replace Shellcode
    let buf: [u8; 3] = [0x41, 0x41, 0x41]; 

    pack.addint(23316)?; // PID
    pack.addbin(&buf)?; // Shellcode

    let buffer = pack.getbuffer()?;
    let args = Vec::from_hex(hex::encode(&buffer))?;

    let coffee = CoffeeLdr::new("examples/ntcreatethread.x64.o")?;
    let output = coffee.run("go", Some(args.as_ptr() as _), Some(args.len()))?;
    println!("{output}");

    Ok(())
}

#[test]
fn test_bof_dir() -> Result<(), Box<dyn std::error::Error>> {
    let mut pack = BeaconPack::default();

    pack.addstr("C:\\")?;

    let buffer = pack.getbuffer()?;
    let args = Vec::from_hex(hex::encode(&buffer))?;

    let coffee = CoffeeLdr::new("examples/dir.x64.o")?;
    let output = coffee.run("go", Some(args.as_ptr() as _), Some(args.len()))?;
    println!("{output}");

    Ok(())
}

#[test]
fn test_buffer_memory() -> Result<(), Box<dyn std::error::Error>> {
    let buffer = include_bytes!("../examples/whoami.x64.o");

    let coffee = CoffeeLdr::new(buffer)?;
    let output = coffee.run("go", None, None)?;
    println!("{output}");

    Ok(())
}

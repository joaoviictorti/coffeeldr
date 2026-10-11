use coffeeldr::{beacon::BeaconPack, CoffLdr, Result};

#[test]
fn test_dir() -> Result<()> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/dir.x64.o"
    );

    let mut pack = BeaconPack::default();
    pack.addstr("C:\\Windows")?;
    
    let args = pack.get_buffer_hex()?;
    let mut ldr = CoffLdr::new(path)?;
    let output = ldr.run("go", Some(args.as_ptr() as _), Some(args.len()))?;

    assert!(
        output.contains("Directory of")
            || output.contains("File(s)")
            || output.contains("Dir(s)")
            || output.contains("bytes"),
        "dir output does not look valid: {output}"
    );

    Ok(())
}
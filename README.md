# coffeeldr

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]

A COFF loader written in Rust, designed to run COFF files on Windows.

## Getting started

Add `coffeeldr` to your project:

```bash
cargo add coffeeldr
```

## Usage

### Running COFF File

To load and execute a COFF file from the filesystem:
```rust
use coffeeldr::CoffLdr;

let mut loader = CoffLdr::new("whoami.o").expect("Failed to load COFF from file");
let output = loader.run("go", None, None).expect("Failed to execute COFF");
println!("{output}");
```

For more information, including a more detailed overview of coffeeldr, [visit the documentation](https://docs.rs/coffeeldr).

## References

I want to express my gratitude to these projects that inspired me to create `coffeeldr` and contribute with some features:

- [Havoc](https://github.com/HavocFramework/Havoc)
- [otterhacker.github.io](https://otterhacker.github.io/Malware/CoffLoader.html)
- [Trustedsec - COFFLoader](https://github.com/trustedsec/COFFLoader)

## License

coffeeldr is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/joaoviictorti/coffeeldr/tree/main/LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/joaoviictorti/coffeeldr/tree/main/LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in coffeeldr
by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any
additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/coffeeldr?logo=rust
[crate-link]: https://crates.io/crates/coffeeldr
[docs-image]: https://docs.rs/coffeeldr/badge.svg
[docs-link]: https://docs.rs/coffeeldr/
[build-image]: https://github.com/joaoviictorti/coffeeldr/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/joaoviictorti/coffeeldr/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

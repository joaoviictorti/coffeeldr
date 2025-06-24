# coffeeldr 🦀 

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![crate](https://img.shields.io/crates/v/coffeeldr.svg)
![docs](https://docs.rs/coffeeldr/badge.svg)
![Forks](https://img.shields.io/github/forks/joaoviictorti/coffeeldr)
![Stars](https://img.shields.io/github/stars/joaoviictorti/coffeeldr)
![License](https://img.shields.io/github/license/joaoviictorti/coffeeldr)

`coffeeldr` is a modern and lightweight COFF (Common Object File Format) loader for Windows written in Rust, designed to run COFF files on Windows. It supports both 32-bit and 64-bit architectures and allows you to load and execute COFF files from files or memory buffers with Rust’s safety and performance guarantees.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Loading from File](#loading-from-file)
  - [Loading from Buffer](#loading-from-buffer)
  - [Executing a COFF File](#executing-a-coff-file)
  - [Using Module Stomping](#using-module-stomping)
- [CLI](#cli)
  - [Input Processing in CLI](#input-processing-in-cli)
  - [Using Module Stomping via CLI](#using-module-stomping-via-cli)
  - [CLI Help](#cli-help)
- [Contributing to coffeeldr](#contributing-to-coffeeldr)
- [References](#references)
- [License](#license)

## Features

- ✅ Supports `#[no_std]` environments (with `alloc`).
- ✅ Load COFF files from disk or in-memory buffers.
- ✅ Load COFF files with module stomping.
- ✅ Compatible with `x64` and `x86` architecture.
- ✅ Memory management: Automatically adjusts memory protections to ensure execution (read, write, execute permissions).
- ✅ Dynamic relocation handling.
- ✅ Fully written in Rust with safety and performance in mind.
- ✅ Easy CLI integration with flexible input handling.

## Installation

Add `coffeeldr` to your project by updating your `Cargo.toml`:

```powershell
cargo add coffeeldr
```

## Usage

### Loading from File

To load a COFF file from the filesystem:
```rust
use coffeeldr::CoffeeLdr;

let mut loader = CoffeeLdr::new("path/to/coff_file.o");
match loader {
    Ok(ldr) => {
        println!("COFF successfully loaded from file!");
        // Execute the entry point or manipulate the COFF as needed
    },
    Err(e) => println!("Error loading COFF: {:?}", e),
}
```

### Loading from Buffer

To load a COFF from an in-memory buffer:
```rust
use coffeeldr::CoffeeLdr;

let coff_data = include_bytes!("path/to/coff_file.o");
let mut loader = CoffeeLdr::new(coff_data);
match loader {
    Ok(ldr) => {
        println!("COFF successfully loaded from buffer!");
        // Execute the entry point or manipulate the COFF as needed
    },
    Err(e) => println!("Error loading COFF: {:?}", e),
}
```

### Executing a COFF File

Once the COFF file is loaded, you can execute it by specifying the entry point:
```rust
let mut coffee = CoffeeLdr::new("path/to/coff_file.o").unwrap();
coffee.run("entry_point_function_name", None, None).unwrap();
```

### Using Module Stomping

Module stomping replaces the `.text` section of a loaded module with the COFF code.
```rs
let mut coffee = CoffeeLdr::new("path/to/coff_file.o")?
    .with_module_stomping("xpsservices.dll"); // specify the module to stomp

coffee.run("go", None, None)?;
```

## CLI

`coffeeldr` also provides a convenient CLI tool for interacting with COFF files directly from the command line.

Example Command:
```cmd
coffee.exe --bof path/to/coff_file.o --entrypoint go
```

### Input Processing in CLI

These are the types of parameters that the tool accepts for processing:

- `/short:<value>`: Adds a short (`i16`) value.
- `/int:<value>`: Adds an integer (`i32`) value.
- `/str:<value>`: Adds a string.
- `/wstr:<value>`: Adds a wide string.
- `/bin:<base64-data>`: Adds binary data decoded from `base64`.

Example command using [`ntcreatethread.o`](https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/Injection/ntcreatethread/ntcreatethread.x64.o):
```cmd
coffee.exe --bof ntcreatethread.o -e go /int:4732 /bin:Y29mZmVlbGRy..
```

Another example using [`dir.o`](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/SA/dir/dir.x64.o):
```cmd
coffee.exe --bof dir.o -e go /str:C:\
```

### Using Module Stomping via CLI

When using the `--stomping <module>` flag, coffeeldr will identify the `.text` section of the specified module and overwrite its contents with the loaded COFF payload

```cmd
coffee.exe --bof whoami.o -e go --stomping xpsservices.dll
```

### CLI Help

```text
A COFF (Common Object File Format) loader written in Rust

Usage: coffee.exe [OPTIONS] --bof <BOF> [INPUTS]...

Arguments:
  [INPUTS]...  Multiple arguments in the format `/short:<value>`, `/int:<value>`, `/str:<value>`, `/wstr:<value>`, `/bin:<base64-data>`

Options:
  -b, --bof <BOF>                The command to be executed
  -e, --entrypoint <ENTRYPOINT>  Entrypoint to use in the execution [default: go]
      --stomping <STOMPING>      Enables module stomping (e.g., --stomping xpsservices.dll)
  -v, --verbose...               Verbose mode (-v, -vv, -vvv, etc.)
  -h, --help                     Print help
```

## Contributing to coffeeldr
To contribute to **coffeeldr**, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`.
4. Push your changes to your branch: `git push origin <branch_name>`.
5. Create a pull request.

Alternatively, consult the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests) on how to create a pull request.

## References

I want to express my gratitude to these projects that inspired me to create `coffeeldr` and contribute with some features:

- [Havoc](https://github.com/HavocFramework/Havoc)
- [otterhacker.github.io](https://otterhacker.github.io/Malware/CoffLoader.html)
- [Trustedsec - COFFLoader](https://github.com/trustedsec/COFFLoader)

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE) file for details.
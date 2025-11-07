use clap_verbosity_flag::Verbosity;
use log::{error, info};
use clap::Parser;
use base64::{engine::general_purpose, Engine as _};
use coffeeldr::{BeaconPack, CoffeeLdr};

mod logging;

/// The main command-line interface struct.
#[derive(Parser)]
#[clap(author="joaoviictorti", about="A COFF loader written in Rust")]
pub struct Cli {
    /// The command to be executed.
    #[arg(short, long, required = true)]
    pub bof: String,

    /// Entrypoint to use in the execution.
    #[arg(short, long, default_value_t = default_entrypoint())]
    pub entrypoint: String,

    /// Multiple arguments in the format `/short:<value>`, `/int:<value>`, `/str:<value>`, `/wstr:<value>`, `/bin:<base64-data>`, `/bin_path:<bin-file-path>`
    #[arg(value_parser)]
    pub inputs: Option<Vec<String>>,

    /// Enables module stomping (e.g., --stomping chakra.dll)
    #[arg(long)]
    pub stomping: Option<String>,

    #[command(flatten)]
    pub verbose: Verbosity,
}

/// Function to set the default entrypoint value based on the architecture.
fn default_entrypoint() -> String {
    if cfg!(target_pointer_width = "64") {
        "go".to_string()
    } else {
        "_go".to_string()
    }
}

/// Processes each input according to its type and adds it to the buffer.
fn process_input(input: &str, pack: &mut BeaconPack) -> Result<(), String> {
    if input.starts_with("/short:") {
        let short_data = &input[7..];
        match short_data.parse::<i16>() {
            Ok(value) => {
                pack.addshort(value).map_err(|e| format!("Error adding short: {e}"))?;
                info!("Added short: {}", value);
            }
            Err(e) => return Err(format!("Error converting to short: {e}")),
        }

    } else if input.starts_with("/int:") {
        let int_data = &input[5..];
        match int_data.parse::<i32>() {
            Ok(value) => {
                pack.addint(value).map_err(|e| format!("Error adding int: {e}"))?;
                info!("Added int: {}", value);
            }
            Err(e) => return Err(format!("Error converting to int: {e}")),
        }

    } else if input.starts_with("/str:") {
        let str_data = &input[5..];
        pack.addstr(str_data).map_err(|e| format!("Error adding str: {e}"))?;
        info!("Added string: {}", str_data);

    } else if input.starts_with("/wstr:") {
        let wstr_data = &input[6..];
        pack.addwstr(wstr_data).map_err(|e| format!("Error adding wide wstr: {e}"))?;
        info!("Added wide string: {}", wstr_data);
    
    } else if input.starts_with("/bin:") {
        let base64_data = &input[5..];
        match general_purpose::STANDARD.decode(base64_data) {
            Ok(decoded) => {
                pack.addbin(&decoded).map_err(|e| format!("Error adding bin: {e}"))?;
                info!("Added binary: {}", base64_data);
            }
            Err(e) => return Err(format!("Error decoding Base64: {e}")),
        }

    } else if input.starts_with("/bin_path:") {
        let file_path = &input[10..];
        let file_fd = std::path::Path::new(file_path);
        if !file_fd.exists() {
            return Err(format!("File not found: {}", file_path));
        }
        match std::fs::read(file_fd) {
            Ok(file_data) => {
                pack.addbin(&file_data).map_err(|e| format!("Error adding bin: {e}"))?;
                info!("Added binary file: {}", file_path);
            },
            Err(e) => return Err(format!("Error reading file '{}': {e}", file_path)),
        }
    } else {
        return Err(format!("Invalid input format: {input}"));
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initializes global logger
    logging::init_logger(&cli.verbose);

    // Initialize the buffer
    let mut pack = BeaconPack::default();

    // Process inputs if provided
    if let Some(inputs) = &cli.inputs {
        for input in inputs {
            process_input(input, &mut pack)
                .map_err(|e| error!("{e}"))
                .map_err(|_| "Input processing failed")?;
        }
    } else {
        info!("No inputs were provided.");
    }

    // Prepare buffer and length if inputs were provided
    let vec_buffer = if cli.inputs.is_some() {
        // Get the buffer from the pack
        Some(pack.get_buffer_hex()?)
    } else {
        None
    };

    let (buffer, len) = if let Some(ref buf) = vec_buffer {
         // Pass the pointer and length if buffer exists
        (Some(buf.as_ptr() as *mut u8), Some(buf.len()))
    } else {
         // No inputs, pass None
        (None, None)
    };

    // Run CoffeeLdr
    let mut coffee = CoffeeLdr::new(cli.bof.as_str())?;
    coffee = if let Some(ref module_name) = cli.stomping {
        info!("Module stomping enabled: {}", module_name);
        coffee.with_module_stomping(module_name)
    } else {
        coffee
    };

    match coffee.run(&cli.entrypoint, buffer, len) {
        Ok(result) => print!("Output:\n {result}"),
        Err(err_code) => error!("{:?}", err_code),
    }

    Ok(())
}

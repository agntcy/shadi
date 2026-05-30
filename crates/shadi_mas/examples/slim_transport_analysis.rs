#[path = "common/mod.rs"]
mod common;
#[path = "common/slim_transport.rs"]
mod slim_transport;

use common::{parse_output_format, OutputFormat};
use slim_transport::{render_transport_csv, render_transport_summary_text, run_transport_sweep};

fn main() -> Result<(), String> {
    let format = parse_output_format()?;
    let rows = run_transport_sweep()?;

    match format {
        OutputFormat::Summary => print!("{}", render_transport_summary_text(&rows)),
        OutputFormat::Csv => print!("{}", render_transport_csv(&rows)),
    }

    Ok(())
}
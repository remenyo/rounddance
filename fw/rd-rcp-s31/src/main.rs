//! rd-rcp-s31: S31 RCP radio firmware.
//!
//! Thin image over the shared [`rd_rcp`] engine: S31 pins + UART +
//! caps bit, then `run` forever. The PC (`rd-pchost --target s31`)
//! owns the Zigbee stack; this unit only radiates and receives.
//!
//! Phase 2 owns flashing (backup-first, lease, by-id); this crate
//! only builds the image. Pin overrides without source edits:
//! `RD_RCP_RX_PIN` / `RD_RCP_TX_PIN` (decimal, build-time).

use rd_rcp::{pin_or, run, Board};

fn main() {
    // BENCH ADAPTER (rdpc-air 2026-11-04, reverted after the proof):
    // the S31 lab carrier wires its CP2102N bridge to UART0
    // (GPIO59 RX / GPIO58 TX = the S31 UART0 defaults), not to the
    // documented RCP UART1 (GPIO15/16, unconnected on this bench).
    // The RCP wire therefore runs on UART0 here; the IDF console is
    // moved to USB-Serial-JTAG (sdkconfig) so no console byte can
    // interleave with RCP frames. Caps bit stays s31.
    let board = Board {
        uart_num: 0,
        rx_pin: pin_or(option_env!("RD_RCP_RX_PIN"), 59),
        tx_pin: pin_or(option_env!("RD_RCP_TX_PIN"), 58),
        ..Board::s31()
    };
    run(board);
}

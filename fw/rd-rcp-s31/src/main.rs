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
    let board = Board {
        rx_pin: pin_or(option_env!("RD_RCP_RX_PIN"), Board::s31().rx_pin),
        tx_pin: pin_or(option_env!("RD_RCP_TX_PIN"), Board::s31().tx_pin),
        ..Board::s31()
    };
    run(board);
}

//! Steering election: survey two beacons, close the scan window,
//! and elect the permit-open network — while a lone phantom row can
//! never win. Covers the N-sighting join decision.
//!
//! Run: `cargo run -p rounddance --example steering_election`

use rounddance::commission::{
    BeaconSurveyEntry, ChannelMask, LinkEvidencePolicy, SteeringMachine, SteeringState,
};

fn entry(pan: u16, permit: bool) -> BeaconSurveyEntry {
    BeaconSurveyEntry {
        pan_id: pan,
        channel: 15,
        lqi: 200,
        rssi: -40,
        permit_joining: permit,
        router_capacity: true,
        end_device_capacity: true,
        protocol_version: 2,
    }
}

fn main() {
    let mut sm = SteeringMachine::new();
    sm.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .expect("scan opens");
    sm.ingest(entry(0xc601, true)).expect("row in");
    sm.ingest(entry(0xc601, true)).expect("row in");
    sm.ingest(entry(0xee2e, false)).expect("row in");
    sm.finish_scan(&LinkEvidencePolicy::default());

    assert_eq!(sm.state(), SteeringState::CandidateSelected);
    let elected = sm.candidate().expect("a winner").pan_id;
    assert_eq!(elected, 0xc601);
    println!("ELECTED pan={elected:#06x} (permit-open, twice sighted)");

    // A lone phantom row parks the window instead of electing.
    let mut sm2 = SteeringMachine::new();
    sm2.begin_scan(ChannelMask::from_list(&[15]).unwrap(), 3)
        .expect("scan opens");
    sm2.ingest(entry(0x9999, true)).expect("row in");
    sm2.finish_scan(&LinkEvidencePolicy::default());
    assert_eq!(sm2.state(), SteeringState::NoSuitableNetwork);
    println!("PHANTOM single sighting refuses to elect, as designed");
}

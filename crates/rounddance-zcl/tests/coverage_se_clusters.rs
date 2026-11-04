//! Coverage vectors for the Smart Energy profile cluster clauses
//! (doc `07-5356-22`, annex D): DRLC (D.2), Metering (D.3), Price
//! (D.4), Messaging (D.5), and Key Establishment (C.3.1), plus
//! explicit deferral pins for the tunneling / prepayment / calendar /
//! device-management / events / OTA bodies that stay out of scope.
//!
//! The DRLC and Messaging modules ship as `src/drlc.rs` /
//! `src/messaging.rs` and are used through the
//! `rounddance_zcl::{drlc, messaging}` re-exports.
//!
//! Each test names the requirement ID it verifies. Byte strings are
//! hand-computed from the paraphrased layouts in the cited modules —
//! never copied from spec text (D1, `SCOPE.md` §2). Corpus-mined IDs
//! are reused verbatim; repo-minted IDs are MINTED-pending-confirm.
//!
//! Anchor cites below are Smart Energy PDF page ranges (`SE PDF
//! pp. X-Y`, from the document table of contents) for profile
//! clauses, plus extraction line anchors (`pNNNN-Lxxx`) into the
//! corpus mirror of doc `07-5123-08` (prefix `ZCL`) where the shared
//! cluster behavior lives.

pub use rounddance_zcl::attrs;
pub use rounddance_zcl::behavior;
pub use rounddance_zcl::cluster;
pub use rounddance_zcl::frame;
pub use rounddance_zcl::types;
pub use rounddance_zcl::Error;
pub use rounddance_zcl::ZclStatus;

use rounddance_zcl::{drlc, messaging};

use rounddance_zcl::cluster::ClusterDef;
use rounddance_zcl::dispatch::Endpoint;
use rounddance_zcl::{keyest, metering, mirror, notify, price, supply};

// ---- SE D.2 DRLC profile rules (SE PDF pp. 292-324) ---------

// 07-5356-22-D21-01: the SE profile carries the same DRLC cluster.
#[test]
fn vector_se_drlc_identity_07_5356_22_d21_01() {
    assert_eq!(drlc::CLUSTER_ID, 0x0701);
    assert_eq!(drlc::REVISION, 2);
    // The ESI (server) label from the ZCL classification carries over:
    // server emits events, clients report and fetch.
    assert_eq!(drlc::ServerDef.cluster_id(), drlc::ClientDef.cluster_id());
    let rx: Vec<u8> = drlc::ClientDef
        .generated_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(
        rx,
        vec![
            drlc::CMD_REPORT_EVENT_STATUS,
            drlc::CMD_GET_SCHEDULED_EVENTS
        ]
    );
}

// 07-5356-22-D24-01: client enrollment/randomization defaults.
#[test]
fn vector_se_drlc_client_defaults_07_5356_22_d24_01() {
    let store = drlc::client_store(0xffff).unwrap();
    // All-groups enrollment (IHDs use 0xFFFF class to see everything).
    assert_eq!(drlc::group_of(&store), 0x00);
    assert_eq!(drlc::class_of(&store), 0xffff);
    // Windows stay inside the valid range.
    const { assert!(drlc::DEFAULT_START_RANDOMIZATION_MINUTES <= drlc::MAX_RANDOMIZATION_MINUTES) };
}

// 07-5356-22-D24-02: mandatory vs voluntary participation.
#[test]
fn vector_se_drlc_participation_07_5356_22_d24_02() {
    // Conservation appeals stay voluntary ...
    for level in [drlc::CRITICALITY_GREEN, 0x02, 0x06] {
        assert_eq!(
            drlc::criticality_participation(level),
            Some(drlc::PARTICIPATION_VOLUNTARY)
        );
    }
    // ... while emergency/outage/disconnect tiers are mandatory ...
    for level in [
        drlc::CRITICALITY_EMERGENCY,
        drlc::CRITICALITY_PLANNED_OUTAGE,
        drlc::CRITICALITY_SERVICE_DISCONNECT,
    ] {
        assert_eq!(
            drlc::criticality_participation(level),
            Some(drlc::PARTICIPATION_MANDATORY)
        );
    }
    // ... and the utility band is utility-defined.
    assert_eq!(
        drlc::criticality_participation(0x0a),
        Some(drlc::PARTICIPATION_UTILITY)
    );
    assert_eq!(drlc::criticality_participation(0x00), None);
}

// ---- SE D.3 metering profile rules (SE PDF pp. 325-361) -----

// 07-5356-22-D32-01: multiplier/divisor pairing (unitary on zero).
#[test]
fn vector_se_metering_scale_pairing_07_5356_22_d32_01() {
    assert_eq!(metering::CLUSTER_ID, 0x0702);
    // A zero divisor or multiplier collapses to a unitary factor.
    assert_eq!(metering::scaled_value(1000, 1, 0), 1000);
    assert_eq!(metering::scaled_value(1000, 0, 1), 0);
    assert_eq!(metering::scaled_value(52003, 1, 1000), 52);
    let store = metering::server_store().unwrap();
    assert_eq!(metering::scaled_summation(&store), 0);
}

// 07-5356-22-D323-01: profile command identifiers.
#[test]
fn vector_se_metering_commands_07_5356_22_d323_01() {
    assert_eq!(metering::CMD_GET_PROFILE, 0x00);
    assert_eq!(metering::CMD_REQUEST_FAST_POLL, 0x03);
    assert_eq!(metering::CMD_GET_PROFILE_RESPONSE, 0x00);
    assert_eq!(supply::CMD_SET_SUPPLY_STATUS, 0x0d);
    assert_eq!(supply::CMD_SET_UNCONTROLLED_FLOW, 0x0e);
    // Mirror setup endpoints refuse the broadcast/reserved markers.
    assert!(mirror::endpoint_is_grantable(mirror::ENDPOINT_MIN));
    assert!(!mirror::endpoint_is_grantable(mirror::ENDPOINT_REFUSED));
}

// 07-5356-22-D344-01: two-way mirror notification schemes.
#[test]
fn vector_se_mirror_schemes_07_5356_22_d344_01() {
    assert_eq!(notify::SCHEME_A, 0x01);
    assert_eq!(notify::SCHEME_B, 0x02);
    assert!(notify::scheme_usable(notify::SCHEME_A));
    assert!(notify::scheme_usable(notify::SCHEME_B));
    assert!(!notify::scheme_usable(notify::SCHEME_NONE));
    assert!(!notify::scheme_usable(notify::SCHEME_RESERVED));
    assert!(notify::scheme_predefined(notify::SCHEME_A));
    assert!(!notify::scheme_predefined(notify::SCHEME_GENERIC_MIN));
    // Predefined orders carry only defined nibbles.
    assert!(notify::order_valid(notify::SCHEME_A_ORDER));
    assert!(notify::order_valid(notify::SCHEME_B_ORDER));
}

// ---- SE D.4 price profile rules (SE PDF pp. 362-439) --------

// 07-5356-22-D42-01: delivered/received tariff sections.
#[test]
fn vector_se_price_tariff_sections_07_5356_22_d42_01() {
    assert_eq!(price::CLUSTER_ID, 0x0700);
    assert_eq!(price::TARIFF_DELIVERED, 0x00);
    assert_eq!(price::TARIFF_RECEIVED, 0x01);
    // Pure time-of-use tariffs carry zero thresholds; single-set
    // block tariffs carry blocks-plus-one (capped at fifteen).
    assert_eq!(price::threshold_count_for_tariff(true, 7), 0);
    assert_eq!(price::threshold_count_for_tariff(false, 0), 1);
    assert_eq!(price::threshold_count_for_tariff(false, 3), 3);
    assert_eq!(
        price::threshold_count_for_tariff(false, 99),
        price::MAX_BLOCK_THRESHOLDS as u8
    );
}

// 07-5356-22-D44-01: block charging needs current + upcoming.
#[test]
fn vector_se_price_block_retention_07_5356_22_d44_01() {
    let mut table = price::BlockTable::new();
    assert!(table.is_empty());
    let mk = |issuer: u32, start: u32, dur: u32| price::BlockPeriod {
        provider_id: 1,
        issuer_event_id: issuer,
        start_time: start,
        duration: dur,
        control: 0,
        duration_type: 0,
        tariff_type: price::TARIFF_DELIVERED,
        tariff_resolution: 0,
    };
    table.insert(mk(1, 1000, 10));
    table.insert(mk(2, 2000, 10));
    assert_eq!(table.len(), 2);
    // Newer issuer ids win overlapping periods; cancel removes.
    table.insert(mk(3, 1000, 10));
    assert_eq!(table.len(), 2);
    let mut cancel = mk(3, 1000, 60);
    cancel.start_time = price::BLOCK_START_CANCEL;
    table.insert(cancel);
    assert_eq!(table.len(), 1);
    // Until-changed periods never expire out of the mirror.
    let mut hold = mk(9, 3000, 60);
    hold.duration = price::BLOCK_DURATION_UNTIL_CHANGED;
    table.insert(hold);
    assert!(table.mirror_for(9_000_000).is_some());
}

// 07-5356-22-D423-01: price command identifiers.
#[test]
fn vector_se_price_commands_07_5356_22_d423_01() {
    assert_eq!(price::CMD_GET_CURRENT_PRICE, 0x00);
    assert_eq!(price::CMD_GET_SCHEDULED_PRICES, 0x01);
    assert_eq!(price::CMD_PRICE_ACK, 0x02);
    assert_eq!(price::CMD_PUBLISH_PRICE, 0x00);
    assert_eq!(price::CMD_GET_TIER_LABELS, 0x0a);
    assert_eq!(price::CMD_PUBLISH_TIER_LABELS, 0x08);
    // Acknowledgement control bit semantics.
    let ev = price::PublishPrice {
        provider_id: 0,
        rate_len: 0,
        rate_label: [0u8; price::MAX_LABEL],
        issuer_event_id: 0,
        current_time: 0,
        unit_of_measure: 0,
        currency: 0,
        trailing_tier: 0,
        tiers_register: 0,
        start_time: 0,
        duration_min: 0,
        price: 0,
    };
    assert!(ev.ack_required(price::PRICE_CTRL_ACK_REQUIRED));
    assert!(!ev.ack_required(0x00));
}

// ---- SE D.5 messaging profile rules (SE PDF pp. 440-457) ----

// 07-5356-22-D52-01: the SE profile carries the same cluster.
#[test]
fn vector_se_messaging_identity_07_5356_22_d52_01() {
    assert_eq!(messaging::CLUSTER_ID, 0x0703);
    // No attributes on either side; the command tables ascend.
    assert!(messaging::ServerDef.attributes().is_empty());
    let tx: Vec<u8> = messaging::ServerDef
        .generated_commands()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(
        tx,
        vec![
            messaging::CMD_DISPLAY_MESSAGE,
            messaging::CMD_CANCEL_MESSAGE,
            messaging::CMD_DISPLAY_PROTECTED_MESSAGE,
            messaging::CMD_CANCEL_ALL_MESSAGES,
        ]
    );
}

// 07-5356-22-D52-02: confirmation-gated messages persist visibly.
#[test]
fn vector_se_messaging_confirmation_flow_07_5356_22_d52_02() {
    let mk = |id: u32, control: u8| messaging::DisplayMessage {
        message_id: id,
        control,
        start_time: messaging::START_NOW,
        duration_min: messaging::DURATION_UNTIL_CHANGED,
        len: 1,
        text: [0x42u8; messaging::MAX_MESSAGE],
        ext_control: None,
    };
    // Until-changed messages never expire by clock math ...
    assert!(messaging::message_active(&mk(1, 0x00), u32::MAX));
    // ... while bounded messages end past start + duration (the
    // start here is START_NOW = 0).
    let bounded = messaging::DisplayMessage {
        duration_min: 10,
        ..mk(2, 0x00)
    };
    assert!(messaging::message_active(&bounded, 10 * 60));
    assert!(!messaging::message_active(&bounded, 10 * 60 + 1));
    // Unsent (future-start) messages are not active yet.
    let future = messaging::DisplayMessage {
        start_time: 5000,
        ..mk(3, 0x00)
    };
    assert!(!messaging::message_active(&future, 4999));
}

// ---- SE C.3 key establishment (ZCL extraction pp. 849-865) -------------

// 07-5356-22-C311-01: suite negotiation shape.
#[test]
fn vector_se_keyest_suites_07_5356_22_c311_01() {
    assert_eq!(keyest::CLUSTER_ID, 0x0800);
    assert_eq!(keyest::SUITE_1, 0x0001);
    assert_eq!(keyest::SUITE_2, 0x0002);
    assert!(keyest::is_single_suite_bit(keyest::SUITE_1));
    assert!(keyest::is_single_suite_bit(keyest::SUITE_2));
    assert!(!keyest::is_single_suite_bit(
        keyest::SUITE_1 | keyest::SUITE_2
    ));
    assert!(!keyest::is_single_suite_bit(0x0000));
    assert!(keyest::is_known_suite(keyest::SUITE_1));
    assert!(!keyest::is_known_suite(0x0004));
    assert_eq!(
        keyest::SUPPORTED_SUITE_MASK,
        keyest::SUITE_1 | keyest::SUITE_2
    );
    assert_eq!(keyest::CMD_INITIATE_REQ, 0x00);
    assert_eq!(keyest::CMD_TERMINATE, 0x03);
    assert_eq!(keyest::TERM_UNSUPPORTED_SUITE, 0x05);
    assert_eq!(keyest::MAX_GENERATE_TIME, 0xfe);
    let _ = keyest::server_store().unwrap();
}

// ---- explicit deferral pins (out-of-scope bodies) --------------------

// 07-5356-22-D60/D70: tunneling + prepayment stay unmodeled here.
#[test]
fn vector_se_tunnel_prepay_deferred_07_5356_22_d60_01() {
    let mut ep = Endpoint::new();
    ep.add(&drlc::ServerDef).unwrap();
    ep.add(&messaging::ServerDef).unwrap();
    // Tunneling (0x0704) and prepayment (0x0705) bodies carry
    // transfer/debt state machines with no bounded model in this
    // crate: they resolve to no definition (explicit follow-up).
    for id in [0x0704u16, 0x0705] {
        assert!(
            ep.find(id).is_none(),
            "cluster {id:#06x} unexpectedly modeled"
        );
    }
    // The same holds for calendar / device-management / events /
    // energy-management / MDU / sub-GHz clusters.
    for id in [0x0706u16, 0x0707, 0x0708, 0x0709, 0x070a, 0x070b] {
        assert!(
            ep.find(id).is_none(),
            "cluster {id:#06x} unexpectedly modeled"
        );
    }
}

// 07-5356-22-D80: OTA bootload belongs to the sibling image path.
#[test]
fn vector_se_ota_sibling_scope_07_5356_22_d80_01() {
    // No OTA cluster definition lives in this crate; the Default
    // Response triage is cluster-agnostic and keeps working for any
    // future registration through the same endpoint registry.
    let mut ep = Endpoint::new();
    ep.add(&drlc::ServerDef).unwrap();
    assert!(ep.find(0x0019).is_none());
}

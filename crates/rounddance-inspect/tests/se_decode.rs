//! Wave-44 Smart-Energy + key-establishment decode depth and session
//! save/load goldens.
//!
//! All frames are built with the repo's own codecs or hand-assembled
//! from documented layouts; no lab captures exist for SE traffic (the
//! only `~/hwscratch` pcap is a wave-41 beacon baseline), so the
//! wave-40/41 precedent applies: repo-codec-built frames, no new
//! captures taken.

use rounddance_inspect::{chain, report, session, tree};

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

/// SE profile id carried on the APS envelope of these goldens.
const SE_PROFILE: u16 = 0x0109;

/// Wrap a ZCL payload in APS + NWK + MAC (short->short, PAN 0x3761).
fn wrap_full_frame(
    zcl: &[u8],
    cluster_id: u16,
    profile_id: u16,
    nwk_seq: u8,
    aps_ctr: u8,
    src: u16,
    dst: u16,
) -> Vec<u8> {
    let aps = rounddance_aps::frame::DataHeader {
        control: rounddance_aps::frame::FrameControl::data(
            rounddance_aps::frame::DeliveryMode::Unicast,
        ),
        dest: rounddance_aps::frame::DataDest::Unicast { dst_endpoint: 1 },
        cluster_id,
        profile_id,
        src_endpoint: 1,
        counter: aps_ctr,
        ext: None,
    };
    let mut aps_buf = [0u8; 256];
    let an = aps.encode_into(zcl, &mut aps_buf).unwrap();

    let nwk = rounddance_nwk::frame::NwkHeader::minimal(
        rounddance_nwk::frame::FrameControl::data(),
        dst,
        src,
        30,
        nwk_seq,
    );
    let mut nwk_buf = [0u8; 320];
    let nn = nwk.encode_into(&aps_buf[..an], &mut nwk_buf).unwrap();

    let mut frame = vec![0x41, 0x88, 0x5a];
    frame.extend_from_slice(&0x3761u16.to_le_bytes());
    frame.extend_from_slice(&dst.to_le_bytes());
    frame.extend_from_slice(&src.to_le_bytes());
    frame.extend_from_slice(&nwk_buf[..nn]);
    frame
}

/// Cluster-specific ZCL frame: control 0x01 = to server, 0x09 = to
/// client (direction bit 0x08).
fn zcl_cluster(cmd: u8, to_client: bool, tsn: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![if to_client { 0x09 } else { 0x01 }, tsn, cmd];
    out.extend_from_slice(body);
    out
}

fn dissect_se(zcl: &[u8], cluster_id: u16) -> tree::ZclNode {
    let frame = wrap_full_frame(zcl, cluster_id, SE_PROFILE, 9, 7, 0x1234, 0x5678);
    let tree = chain::dissect(&frame).unwrap();
    let z = tree.zcl().expect("zcl node");
    assert_eq!(z.cluster_id, cluster_id);
    assert_eq!(z.profile_id, SE_PROFILE);
    z
}

// ---------------------------------------------------------------------------
// Metering 0x0702.
// ---------------------------------------------------------------------------

#[test]
fn se_metering_get_profile_req() {
    use rounddance_zcl::metering as M;
    let req = M::GetProfileRequest {
        channel: M::CHANNEL_DELIVERED,
        end_time: 0x1234_5678,
        periods: 5,
    };
    let mut body = [0u8; 8];
    let n = M::encode_get_profile(&req, &mut body).unwrap();
    let z = dissect_se(
        &zcl_cluster(M::CMD_GET_PROFILE, false, 0x42, &body[..n]),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Metering {
            cmd: 0x00,
            arg0: M::CHANNEL_DELIVERED,
            arg1: 5,
            arg2: 0x1234_5678,
        }
    );
    assert_eq!(z.direction, 0);
    let text = report::to_text(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(M::CMD_GET_PROFILE, false, 0x42, &body[..n]),
            M::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(text.contains("metering cmd=0x00"), "{text}");
    let json = report::to_json(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(M::CMD_GET_PROFILE, false, 0x42, &body[..n]),
            M::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(json.contains("\"kind\":\"metering\""), "{json}");
    assert!(json.contains("\"cluster\":1794"), "{json}");
}

#[test]
fn se_metering_get_profile_rsp() {
    use rounddance_zcl::metering as M;
    // Genuine codec-produced response body via the profile backlog.
    let mut backlog = M::ProfileBuffer::new();
    backlog.record(0x0000_aabb, 0x1111_2222);
    backlog.record(0x0000_ccdd, 0x3333_4444);
    let req = M::GetProfileRequest {
        channel: M::CHANNEL_DELIVERED,
        end_time: 0,
        periods: 2,
    };
    let mut body = [0u8; 64];
    let n = backlog.answer(&req, &mut body).unwrap();
    assert!(n >= 7 + 2 * 3);
    let z = dissect_se(
        &zcl_cluster(M::CMD_GET_PROFILE_RESPONSE, true, 0x42, &body[..n]),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Metering {
            cmd: 0x00,
            arg0: M::PROFILE_STATUS_SUCCESS,
            arg1: 2,
            arg2: 0x3333_4444,
        }
    );
    assert_eq!(z.direction, 1);
    let text = report::to_text(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(M::CMD_GET_PROFILE_RESPONSE, true, 0x42, &body[..n]),
            M::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(text.contains("metering cmd=0x00"), "{text}");
}

#[test]
fn se_metering_fast_poll_shapes() {
    use rounddance_zcl::metering as M;
    // Request: period seconds + duration minutes.
    let z = dissect_se(
        &zcl_cluster(M::CMD_REQUEST_FAST_POLL, false, 0x01, &[7, 15]),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Metering {
            cmd: 0x03,
            arg0: 7,
            arg1: 15,
            arg2: 0,
        }
    );
    // Response: period + end time.
    let mut rsp = vec![7u8];
    rsp.extend_from_slice(&0x5555_6666u32.to_le_bytes());
    let z = dissect_se(
        &zcl_cluster(M::CMD_FAST_POLL_RESPONSE, true, 0x01, &rsp),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Metering {
            cmd: 0x03,
            arg0: 7,
            arg1: 0,
            arg2: 0x5555_6666,
        }
    );
    // Truncated request (1 octet) degrades to Unknown, never errors.
    let z = dissect_se(
        &zcl_cluster(M::CMD_REQUEST_FAST_POLL, false, 0x01, &[7]),
        M::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x03 });
    // Short response (< 7 octets) degrades to Unknown.
    let z = dissect_se(
        &zcl_cluster(M::CMD_GET_PROFILE_RESPONSE, true, 0x01, &[1, 2, 3]),
        M::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x00 });
    // Wrong-length fast-poll response and unmodeled ids Unknown.
    let z = dissect_se(
        &zcl_cluster(M::CMD_FAST_POLL_RESPONSE, true, 0x01, &[7, 8, 9]),
        M::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x03 });
    let z = dissect_se(&zcl_cluster(0x05, false, 0x01, &[1, 2]), M::CLUSTER_ID);
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x05 });
}

#[test]
fn se_metering_submodule_cmds_stay_unknown() {
    use rounddance_zcl::metering as M;
    use rounddance_zcl::{mirror, snapshot};
    // Mirror / snapshot commands ride 0x0702 but have no summary.
    let z = dissect_se(
        &zcl_cluster(mirror::CMD_REQUEST_MIRROR, false, 0x01, &[]),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Unknown {
            cmd: mirror::CMD_REQUEST_MIRROR,
        }
    );
    let z = dissect_se(
        &zcl_cluster(snapshot::CMD_GET_SNAPSHOT, false, 0x01, &[1, 2, 3, 4]),
        M::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Unknown {
            cmd: snapshot::CMD_GET_SNAPSHOT,
        }
    );
    // Truncated GetProfile (dangling octet) degrades to Unknown.
    let z = dissect_se(
        &zcl_cluster(M::CMD_GET_PROFILE, false, 0x01, &[0, 1, 2]),
        M::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x00 });
}

// ---------------------------------------------------------------------------
// Price 0x0700.
// ---------------------------------------------------------------------------

#[test]
fn se_price_publish_and_ack() {
    use rounddance_zcl::price as P;
    let mut label = [0u8; P::MAX_LABEL];
    label[..3].copy_from_slice(b"kWh");
    let ev = P::PublishPrice {
        provider_id: 0x1111_1111,
        rate_len: 3,
        rate_label: label,
        issuer_event_id: 0x2222_2222,
        current_time: 0x3333_3333,
        unit_of_measure: 0,
        currency: 0x0348,
        trailing_tier: 0x21,
        tiers_register: 0x11,
        start_time: 0,
        duration_min: 0xffff,
        price: 0x4444_4444,
    };
    let mut body = [0u8; 64];
    let n = P::encode_publish_price(&ev, &mut body).unwrap();
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_PRICE, true, 0x42, &body[..n]),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x00,
            arg0: 0x2222_2222,
            arg1: 0x4444_4444,
        }
    );
    assert_eq!(z.direction, 1);
    let text = report::to_text(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(P::CMD_PUBLISH_PRICE, true, 0x42, &body[..n]),
            P::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(text.contains("price cmd=0x00"), "{text}");
    let json = report::to_json(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(P::CMD_PUBLISH_PRICE, true, 0x42, &body[..n]),
            P::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(json.contains("\"kind\":\"price\""), "{json}");

    // PriceAcknowledgement the other way: issuer + ack time kept.
    let mut ack = [0u8; 16];
    let n = P::encode_price_ack(0x1111_1111, 0x2222_2222, 0x5555_5555, 0x01, &mut ack).unwrap();
    let z = dissect_se(
        &zcl_cluster(P::CMD_PRICE_ACK, false, 0x43, &ack[..n]),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x02,
            arg0: 0x2222_2222,
            arg1: 0x5555_5555,
        }
    );
    assert_eq!(z.direction, 0);
}

#[test]
fn se_price_requests_and_direction_split() {
    use rounddance_zcl::price as P;
    // GetCurrentPrice: 1-octet options; the same id server→client
    // would be a PublishPrice, so a 1-octet 0x00 to-client body is
    // Unknown (too short for the publish prefix).
    let z = dissect_se(
        &zcl_cluster(P::CMD_GET_CURRENT_PRICE, false, 0x01, &[0x01]),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x00,
            arg0: 1,
            arg1: 0,
        }
    );
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_PRICE, true, 0x01, &[0x01]),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x00 });

    // GetScheduledPrices: start + count.
    let mut body = [0u8; 5];
    body[..4].copy_from_slice(&0x7777_8888u32.to_le_bytes());
    body[4] = 3;
    let z = dissect_se(
        &zcl_cluster(P::CMD_GET_SCHEDULED_PRICES, false, 0x01, &body),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x01,
            arg0: 0x7777_8888,
            arg1: 3,
        }
    );

    // GetBlockPeriods: start + max events.
    let z = dissect_se(
        &zcl_cluster(P::CMD_GET_BLOCK_PERIODS, false, 0x01, &body),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x03,
            arg0: 0x7777_8888,
            arg1: 3,
        }
    );

    // Malformed bodies degrade to Unknown: empty GetCurrentPrice,
    // short GetScheduledPrices / PriceAck, bad-count TierLabels.
    let z = dissect_se(
        &zcl_cluster(P::CMD_GET_CURRENT_PRICE, false, 0x01, &[]),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x00 });
    let z = dissect_se(
        &zcl_cluster(P::CMD_GET_SCHEDULED_PRICES, false, 0x01, &[1, 2, 3]),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x01 });
    let z = dissect_se(
        &zcl_cluster(P::CMD_PRICE_ACK, false, 0x01, &[1, 2, 3]),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x02 });
    // TierLabels claiming 5 entries exceeds the bounded scratch.
    let mut over = vec![0u8; 15];
    over[..4].copy_from_slice(&0x1111_1111u32.to_le_bytes());
    over[4..8].copy_from_slice(&0x2222_2222u32.to_le_bytes());
    over[8..12].copy_from_slice(&0x3333_3333u32.to_le_bytes());
    over[14] = 5;
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_TIER_LABELS, true, 0x01, &over),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x08 });
    // Short block-period publish and unknown ids either way.
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_BLOCK_PERIOD, true, 0x01, &[1, 2, 3]),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x01 });
    let z = dissect_se(&zcl_cluster(0x09, false, 0x01, &[1]), P::CLUSTER_ID);
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x09 });
    let z = dissect_se(&zcl_cluster(0x09, true, 0x01, &[1]), P::CLUSTER_ID);
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x09 });

    // Tariff-id requests: exact 4-octet bodies; short ones Unknown.
    let mut tariff = [0u8; 4];
    tariff.copy_from_slice(&0x9999_aaaau32.to_le_bytes());
    for cmd in [P::CMD_GET_BLOCK_THRESHOLDS, P::CMD_GET_TIER_LABELS] {
        let z = dissect_se(&zcl_cluster(cmd, false, 0x01, &tariff), P::CLUSTER_ID);
        assert_eq!(
            z.detail,
            tree::ZclDetail::Price {
                cmd,
                arg0: 0x9999_aaaa,
                arg1: 0,
            }
        );
        let z = dissect_se(&zcl_cluster(cmd, false, 0x01, &[1, 2, 3]), P::CLUSTER_ID);
        assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd });
    }
}

#[test]
fn se_price_block_and_tier_publishes() {
    use rounddance_zcl::price as P;
    // PublishBlockPeriod via the cluster codec: issuer + start kept.
    let ev = P::BlockPeriod {
        provider_id: 0x1111_1111,
        issuer_event_id: 0x2222_2222,
        start_time: 0x3333_3333,
        duration: 60,
        control: 0,
        duration_type: 0,
        tariff_type: 0,
        tariff_resolution: 0,
    };
    let mut body = [0u8; 24];
    let n = P::encode_publish_block_period(&ev, &mut body).unwrap();
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_BLOCK_PERIOD, true, 0x42, &body[..n]),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x01,
            arg0: 0x2222_2222,
            arg1: 0x3333_3333,
        }
    );

    // PublishTierLabels hand-built (provider + issuer + tariff +
    // index + total + count + one entry): issuer + count kept.
    let mut body = Vec::new();
    body.extend_from_slice(&0x1111_1111u32.to_le_bytes());
    body.extend_from_slice(&0x2222_2222u32.to_le_bytes());
    body.extend_from_slice(&0x3333_3333u32.to_le_bytes());
    body.push(0); // index
    body.push(1); // total
    body.push(1); // count
    body.push(2); // tier id
    body.push(3); // label len
    body.extend_from_slice(b"mid");
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_TIER_LABELS, true, 0x42, &body),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x08,
            arg0: 0x2222_2222,
            arg1: 1,
        }
    );

    // PublishBlockThresholds hand-built (19-octet header + one empty
    // all-tiers set): issuer + start kept.
    let mut body = Vec::new();
    body.extend_from_slice(&0x1111_1111u32.to_le_bytes());
    body.extend_from_slice(&0x2222_2222u32.to_le_bytes());
    body.extend_from_slice(&0x3333_3333u32.to_le_bytes());
    body.extend_from_slice(&0x4444_4444u32.to_le_bytes());
    body.push(0); // index
    body.push(1); // total (nonzero, index < total)
    body.push(0x01); // sub-control: all-tiers
    body.push(0x00); // tier 0, count 0
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_BLOCK_THRESHOLDS, true, 0x42, &body),
        P::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::Price {
            cmd: 0x06,
            arg0: 0x2222_2222,
            arg1: 0x3333_3333,
        }
    );
    // A zero-total thresholds body fails the codec: Unknown.
    let mut bad = body.clone();
    bad[17] = 0;
    let z = dissect_se(
        &zcl_cluster(P::CMD_PUBLISH_BLOCK_THRESHOLDS, true, 0x42, &bad),
        P::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x06 });
}

// ---------------------------------------------------------------------------
// Key Establishment 0x0800 (decode-only, no crypto).
// ---------------------------------------------------------------------------

#[test]
fn se_keyest_initiate_and_terminate() {
    use rounddance_zcl::keyest as K;
    // Initiate via the cluster codec, either direction: suite +
    // hints kept, certificate never parsed or retained.
    let msg = K::InitiateMsg {
        suite: K::SUITE_1,
        eph_time: 0x0a,
        confirm_time: 0x0b,
        cert: [0x77u8; 48],
    };
    let mut body = [0u8; 64];
    let n = K::encode_initiate(&msg, &mut body).unwrap();
    for to_client in [false, true] {
        let z = dissect_se(
            &zcl_cluster(K::CMD_INITIATE_REQ, to_client, 0x42, &body[..n]),
            K::CLUSTER_ID,
        );
        assert_eq!(
            z.detail,
            tree::ZclDetail::KeyInit {
                suite: K::SUITE_1,
                eph_time: 0x0a,
                confirm_time: 0x0b,
            }
        );
    }
    let text = report::to_text(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(K::CMD_INITIATE_REQ, false, 0x42, &body[..n]),
            K::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(text.contains("keyinit suite=0x0001"), "{text}");
    let json = report::to_json(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(K::CMD_INITIATE_REQ, false, 0x42, &body[..n]),
            K::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(json.contains("\"kind\":\"keyinit\""), "{json}");
    // Truncated initiate (wrong length) degrades to Unknown.
    let z = dissect_se(
        &zcl_cluster(K::CMD_INITIATE_REQ, false, 0x42, &[1, 2, 3]),
        K::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x00 });

    // Terminate via the cluster codec: status + wait + suite kept.
    let term = K::TerminateMsg {
        status: K::TERM_UNSUPPORTED_SUITE,
        wait_s: 30,
        suite: K::SUITE_1,
    };
    let mut tbody = [0u8; 8];
    let n = K::encode_terminate(&term, &mut tbody).unwrap();
    let z = dissect_se(
        &zcl_cluster(K::CMD_TERMINATE, false, 0x42, &tbody[..n]),
        K::CLUSTER_ID,
    );
    assert_eq!(
        z.detail,
        tree::ZclDetail::KeyTerminate {
            status: K::TERM_UNSUPPORTED_SUITE,
            wait_s: 30,
            suite: K::SUITE_1,
        }
    );
    let json = report::to_json(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(K::CMD_TERMINATE, true, 0x42, &tbody[..n]),
            K::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(json.contains("\"kind\":\"keyterm\""), "{json}");
    // Short terminate degrades to Unknown.
    let z = dissect_se(
        &zcl_cluster(K::CMD_TERMINATE, false, 0x42, &[5, 6]),
        K::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x03 });
}

#[test]
fn se_keyest_ephemeral_and_confirm_shapes() {
    use rounddance_zcl::keyest as K;
    // Ephemeral: both wire forms (64-octet expanded, 33-octet
    // compressed) validate by length only — the bytes are never
    // decompressed and no crypto runs.
    for (len, want) in [(K::EPH_LEN, 64u8), (K::EPH_COMPRESSED_LEN, 33u8)] {
        let body = vec![0x02u8; len];
        for to_client in [false, true] {
            let z = dissect_se(
                &zcl_cluster(K::CMD_EPHEMERAL_REQ, to_client, 0x42, &body),
                K::CLUSTER_ID,
            );
            assert_eq!(
                z.detail,
                tree::ZclDetail::KeyMsg {
                    cmd: 0x01,
                    len: want
                }
            );
        }
    }
    // Confirm: exactly 16 octets validate; anything else Unknown.
    let z = dissect_se(
        &zcl_cluster(K::CMD_CONFIRM_REQ, false, 0x42, &[0xabu8; 16]),
        K::CLUSTER_ID,
    );
    assert_eq!(z.detail, tree::ZclDetail::KeyMsg { cmd: 0x02, len: 16 });
    let json = report::to_json(
        &chain::dissect(&wrap_full_frame(
            &zcl_cluster(K::CMD_CONFIRM_REQ, false, 0x42, &[0xabu8; 16]),
            K::CLUSTER_ID,
            SE_PROFILE,
            9,
            7,
            0x1234,
            0x5678,
        ))
        .unwrap(),
    );
    assert!(json.contains("\"kind\":\"keymsg\""), "{json}");
    for len in [0usize, 1, 15, 17, 32, 64] {
        let body = vec![0u8; len];
        let z = dissect_se(
            &zcl_cluster(K::CMD_CONFIRM_REQ, false, 0x42, &body),
            K::CLUSTER_ID,
        );
        assert_eq!(
            z.detail,
            tree::ZclDetail::Unknown { cmd: 0x02 },
            "len {len}"
        );
    }
    for len in [0usize, 1, 20, 32, 34, 63, 65, 100] {
        let body = vec![0u8; len];
        let z = dissect_se(
            &zcl_cluster(K::CMD_EPHEMERAL_REQ, false, 0x42, &body),
            K::CLUSTER_ID,
        );
        assert_eq!(
            z.detail,
            tree::ZclDetail::Unknown { cmd: 0x01 },
            "len {len}"
        );
    }
    // Unmodeled keyest command stays Unknown.
    let z = dissect_se(&zcl_cluster(0x04, false, 0x42, &[1, 2, 3]), K::CLUSTER_ID);
    assert_eq!(z.detail, tree::ZclDetail::Unknown { cmd: 0x04 });
}

// ---------------------------------------------------------------------------
// Session save/load (JSON round trip with schema-version gate).
// ---------------------------------------------------------------------------

/// Genuine captured-air secured NWK frame (pinned octets, wave-36).
const EMBER_U1: [u8; 45] = [
    0x61, 0x88, 0x60, 0x1d, 0xb2, 0x1d, 0x02, 0x00, 0x00, 0x09, 0x12, 0x1d, 0x02, 0x00, 0x00, 0x01,
    0x44, 0x5f, 0x75, 0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x28, 0x04, 0x40, 0x00, 0x00, 0x5f, 0x75,
    0xf4, 0xfe, 0xff, 0xe5, 0xe3, 0x04, 0x00, 0x00, 0xab, 0x53, 0x68, 0xca, 0xee,
];

fn zcl_read_global(tsn: u8, attrs: &[u16]) -> Vec<u8> {
    let h = rounddance_zcl::frame::Header {
        control: rounddance_zcl::frame::FrameControl {
            frame_type: rounddance_zcl::frame::FrameType::Global,
            manufacturer_specific: false,
            direction: rounddance_zcl::frame::Direction::ToServer,
            disable_default_response: false,
        },
        manufacturer_code: None,
        tsn,
        command_id: rounddance_zcl::general::cmd::READ,
    };
    let mut buf = [0u8; 64];
    let n = h.encode_into(&mut buf).unwrap();
    let mut out = buf[..n].to_vec();
    for a in attrs {
        out.extend_from_slice(&a.to_le_bytes());
    }
    out
}

#[test]
fn se_session_save_load_roundtrip() {
    let mut eng = session::SessionEngine::new();
    // Two plain trees from distinct sources (windows + PAN rows).
    for (src, seq) in [(0x1234u16, 9u8), (0x2345u16, 3u8)] {
        let frame = wrap_full_frame(
            &zcl_read_global(0x42, &[0x0000]),
            0x0006,
            0x0104,
            seq,
            seq,
            src,
            0x5678,
        );
        let tree = chain::dissect(&frame).unwrap();
        eng.note_tree(&tree);
    }
    // Secured frame first orphaned, then decryptable after key load.
    let secured = chain::dissect(&EMBER_U1).unwrap();
    eng.note_tree(&secured);
    eng.set_network_key([0xabu8; 16], 0);
    eng.set_network_key([0xcdu8; 16], 1);
    eng.note_tree(&secured);
    assert_eq!(eng.keys().loaded(), 2);

    // A rejoining device keyed by IEEE address (bare NWK PDU with
    // source IEEE, like the wave-41 rejoin golden): covers the
    // non-null ieee path and a PAN-0 network row.
    let ieee = 0x0012_4b00_25ab_cd12u64;
    let mut fc = rounddance_nwk::frame::FrameControl::data();
    fc.src_ieee = true;
    let hdr = rounddance_nwk::frame::NwkHeader {
        control: fc,
        dst_addr: 0x0000,
        src_addr: 0x2222,
        radius: 30,
        seq: 5,
        dst_ieee: None,
        src_ieee: Some(ieee),
        source_route: None,
    };
    let mut nwk_buf = [0u8; 64];
    let n = hdr.encode_into(&[], &mut nwk_buf).unwrap();
    eng.note_tree(&chain::dissect_nwk(&nwk_buf[..n]).unwrap());

    let json = report::session_to_json(&eng);
    assert!(json.contains(&ieee.to_string()));
    let back = report::session_from_json(&json).expect("round trip loads");
    // Byte-identical re-render: every rendered field survived.
    assert_eq!(report::session_to_json(&back), json);
    assert_eq!(back.trees, eng.trees);
    assert_eq!(back.secured_orphan, 1);
    assert_eq!(back.secured_decryptable, 1);
    assert_eq!(back.keys().loaded(), 2);
    let dev = back.device(0x1234).expect("device row");
    assert_eq!(dev.frames, 1);
    assert!(dev.nwk_window.is_some());
    assert!(dev.aps_window.is_some());
    let net = back.network(0x3761).expect("pan row");
    assert_eq!(net.frames, 2);
    assert_eq!(net.devices, 2);
    // IEEE-keyed row survived with its address and window.
    let rejoined = back.device_by_ieee(ieee).expect("ieee row");
    assert_eq!(rejoined.short_addr, 0x2222);
    assert!(rejoined.nwk_window.is_some());
    // Saved text still renders over the restored engine.
    let text = report::session_to_text(&back);
    assert!(text.contains("session: trees=5"));
    assert!(text.contains("key_slots=2"));

    // Leading/trailing whitespace is tolerated.
    let padded = format!("  {json} \n");
    let wpadded = report::session_from_json(&padded).expect("ws loads");
    assert_eq!(report::session_to_json(&wpadded), json);

    // Empty engine round-trips too.
    let empty = session::SessionEngine::new();
    let ej = report::session_to_json(&empty);
    let eback = report::session_from_json(&ej).expect("empty loads");
    assert_eq!(report::session_to_json(&eback), ej);
}

#[test]
fn se_session_load_rejects() {
    use report::SessionLoadError as E;
    // Wrong schema versions gate before any parsing.
    assert!(matches!(report::session_from_json("{\"v\":2,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::BadSchema)));
    assert!(matches!(report::session_from_json("{\"v\":0,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::BadSchema)));
    // Missing version, wrong types, out-of-range scalars.
    assert!(matches!(report::session_from_json("{\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::Malformed)));
    assert!(matches!(report::session_from_json("{\"v\":1,\"trees\":\"x\",\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::Malformed)));
    assert!(matches!(report::session_from_json("{\"v\":1,\"trees\":0,\"devices\":[{\"short\":70000,\"ieee\":null,\"last_seq\":0,\"frames\":0,\"secured\":0,\"nwk\":null,\"aps\":null}],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::Malformed)));
    assert!(matches!(report::session_from_json("{\"v\":1,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":3}}"), Err(E::Malformed)));
    assert!(matches!(
        report::session_from_json("not json"),
        Err(E::Malformed)
    ));
    assert!(matches!(report::session_from_json(""), Err(E::Malformed)));
    assert!(matches!(report::session_from_json("{\"v\":1,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}} trailing"), Err(E::Malformed)));
    // Overflow digits never parse.
    assert!(matches!(report::session_from_json("{\"v\":99999999999999999999999,\"trees\":0,\"devices\":[],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}"), Err(E::Malformed)));

    // Every truncation prefix of a valid snapshot fails typed.
    let mut eng = session::SessionEngine::new();
    let frame = wrap_full_frame(
        &zcl_read_global(0x42, &[0x0000]),
        0x0006,
        0x0104,
        9,
        7,
        0x1234,
        0x5678,
    );
    eng.note_tree(&chain::dissect(&frame).unwrap());
    let json = report::session_to_json(&eng);
    for len in 0..json.len() {
        assert!(
            report::session_from_json(&json[..len]).is_err(),
            "prefix {len}"
        );
    }

    // Over-capacity device table fails typed.
    let mut many = String::from("{\"v\":1,\"trees\":0,\"devices\":[");
    for i in 0..33u16 {
        if i > 0 {
            many.push(',');
        }
        many.push_str(&format!("{{\"short\":{i},\"ieee\":null,\"last_seq\":0,\"frames\":1,\"secured\":0,\"nwk\":null,\"aps\":null}}"));
    }
    many.push_str("],\"networks\":[],\"sec\":{\"decryptable\":0,\"orphan\":0,\"slots\":0}}");
    assert!(matches!(
        report::session_from_json(&many),
        Err(E::Malformed)
    ));
}

// ---------------------------------------------------------------------------
// Robustness: SE sweeps stay typed.
// ---------------------------------------------------------------------------

#[test]
fn se_robustness_sweeps_typed() {
    // Exhaustive 1- and 2-byte payloads over each SE cluster: typed
    // refusal or a graceful summary, never a panic.
    for cluster in [
        rounddance_zcl::metering::CLUSTER_ID,
        rounddance_zcl::price::CLUSTER_ID,
        rounddance_zcl::keyest::CLUSTER_ID,
    ] {
        let mut buf = [0u8; 2];
        for a in 0..=255u16 {
            buf[0] = a as u8;
            // Both direction bits: the first payload byte is the ZCL
            // frame control, so sweep it raw (direction falls out).
            let _ = rounddance_inspect::zcl::decode(&buf[..1], cluster, SE_PROFILE);
            for b in 0..=255u16 {
                buf[1] = b as u8;
                match rounddance_inspect::zcl::decode(&buf, cluster, SE_PROFILE) {
                    Ok(_) => {}
                    Err(e) => assert!(matches!(e, rounddance_inspect::zcl::ZclError::Codec(_))),
                }
            }
        }
    }
    // Every truncation prefix of a valid PublishPrice frame dissects
    // to a sub-tree or a typed error.
    let mut label = [0u8; rounddance_zcl::price::MAX_LABEL];
    label[..3].copy_from_slice(b"kWh");
    let ev = rounddance_zcl::price::PublishPrice {
        provider_id: 1,
        rate_len: 3,
        rate_label: label,
        issuer_event_id: 2,
        current_time: 3,
        unit_of_measure: 0,
        currency: 0x0348,
        trailing_tier: 0x21,
        tiers_register: 0x11,
        start_time: 0,
        duration_min: 0xffff,
        price: 99,
    };
    let mut body = [0u8; 64];
    let n = rounddance_zcl::price::encode_publish_price(&ev, &mut body).unwrap();
    let zcl = zcl_cluster(
        rounddance_zcl::price::CMD_PUBLISH_PRICE,
        true,
        0x42,
        &body[..n],
    );
    let frame = wrap_full_frame(
        &zcl,
        rounddance_zcl::price::CLUSTER_ID,
        SE_PROFILE,
        9,
        7,
        0x1234,
        0x5678,
    );
    for len in 0..frame.len() {
        match chain::dissect(&frame[..len]) {
            Ok(tree) => {
                assert!(!tree.is_empty());
            }
            Err(e) => assert!(matches!(
                e,
                tree::TreeError::Empty
                    | tree::TreeError::MacTruncated
                    | tree::TreeError::MacMalformed
            )),
        }
    }
}

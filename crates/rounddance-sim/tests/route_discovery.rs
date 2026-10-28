//! Three-node route discovery, then a routed frame, replayed twice.
//!
//! Scenario (deterministic, virtual time only — caller milliseconds,
//! no wall clock):
//! 1. Router A discovers router C: A floods a route request, relay B
//!    suppresses its repeat and learns the reverse leg, C answers
//!    with a route reply, B learns the forward leg, A resolves the
//!    session and installs the route via B.
//! 2. A sends a data frame to C: `next_hop` resolves A→B→C, B counts
//!    the forward, C accepts the indication.
//! 3. The whole run replays with an identical event trace.
//!
//! Requirement traceability: `05-3474-23-341-01` (request codec),
//! `05-3474-23-342-01` (reply codec), `05-3474-23-3645-01/02`
//! (table + discovery machine over the router seam), all
//! MINTED-pending-confirm.

use rounddance_nwk::{
    add_path_cost, build_data_header, decode, decode_route_reply, decode_route_request,
    indication_for_local, DiscoverRoute, FrameControl, NldeDataRequest, NwkHeader, RouteReply,
    RouteReplyOptions, RouteRequest, RouteRequestOptions, BROADCAST_ROUTERS,
};
use rounddance_roles::{AgingPolicy, RouterMachine};

const NODE_A: u16 = 0x0001;
const NODE_B: u16 = 0x0002;
const NODE_C: u16 = 0x0003;
const MAX_DEPTH: u8 = 5;

fn active_router() -> RouterMachine {
    let mut r = RouterMachine::new(AgingPolicy::default(), 1_000);
    r.begin_join().unwrap();
    r.join_done(true);
    r
}

/// Command-frame NWK header: broadcasts for flooded requests,
/// unicast toward the next hop otherwise.
fn cmd_header(dst: u16, src: u16, seq: u8) -> NwkHeader {
    NwkHeader::minimal(
        FrameControl::command(),
        dst,
        src,
        MAX_DEPTH.saturating_mul(2),
        seq,
    )
}

fn encode_cmd(header: &NwkHeader, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; header.header_len() + body.len()];
    let n = header.encode_into(body, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Run the discovery-then-route scenario, returning the event trace.
fn run() -> Vec<String> {
    let mut trace = Vec::new();
    let mut a = active_router();
    let mut b = active_router();
    let mut c = active_router();

    // 1. A opens discovery for C and floods the request.
    let rreq_id = a.start_discovery(NODE_C, NODE_A, 0).unwrap();
    trace.push(format!("A opens discovery for C id={rreq_id}"));
    let req = RouteRequest {
        options: RouteRequestOptions::unicast(),
        rreq_id,
        dst_addr: NODE_C,
        path_cost: 0,
        dst_ieee: None,
    };
    let mut body = [0u8; 16];
    let bn = req.encode_into(&mut body).unwrap();
    let air_ab = encode_cmd(&cmd_header(BROADCAST_ROUTERS, NODE_A, 0x10), &body[..bn]);
    trace.push(format!("A floods RREQ len={}", air_ab.len()));

    // 2. B receives the flood: first sighting passes, repeat drops.
    let heard = decode(&air_ab).unwrap();
    assert_eq!(heard.header.dst_addr, BROADCAST_ROUTERS);
    let seen = decode_route_request(heard.payload).unwrap().request;
    assert!(!b.should_suppress_request(NODE_A, seen.rreq_id, 100));
    assert!(b.should_suppress_request(NODE_A, seen.rreq_id, 150));
    trace.push("B suppresses the RREQ repeat".to_string());
    // Reverse leg: B reaches the originator directly.
    b.install_route(NODE_A, NODE_A, add_path_cost(seen.path_cost, 1), 150)
        .unwrap();
    // B re-floods with accumulated cost.
    let mut relay = seen;
    relay.path_cost = add_path_cost(seen.path_cost, 1);
    let mut rbody = [0u8; 16];
    let rn = relay.encode_into(&mut rbody).unwrap();
    let air_bc = encode_cmd(&cmd_header(BROADCAST_ROUTERS, NODE_B, 0x11), &rbody[..rn]);
    b.forward().unwrap();
    trace.push(format!("B re-floods RREQ cost={}", relay.path_cost));

    // 3. C receives the flood: it is the destination, so it answers.
    let heard = decode(&air_bc).unwrap();
    let seen_c = decode_route_request(heard.payload).unwrap().request;
    assert!(!c.should_suppress_request(NODE_A, seen_c.rreq_id, 200));
    c.install_route(NODE_A, NODE_B, add_path_cost(seen_c.path_cost, 1), 200)
        .unwrap();
    trace.push("C learns reverse leg via B".to_string());
    let rep = RouteReply {
        options: RouteReplyOptions::full(),
        rreq_id: seen_c.rreq_id,
        originator: NODE_A,
        responder: NODE_C,
        path_cost: 0,
        originator_ieee: Some(0xAAAA_AAAA_AAAA_0001),
        responder_ieee: Some(0xAAAA_AAAA_AAAA_0003),
    };
    let mut pbody = [0u8; 32];
    let pn = rep.encode_into(&mut pbody).unwrap();
    let air_cb = encode_cmd(&cmd_header(NODE_B, NODE_C, 0x20), &pbody[..pn]);
    trace.push("C unicasts RREP to B".to_string());

    // 4. B receives the reply: learns the forward leg, sends it on.
    let heard = decode(&air_cb).unwrap();
    assert_eq!(heard.header.dst_addr, NODE_B);
    let rep_b = decode_route_reply(heard.payload).unwrap().reply;
    assert_eq!(rep_b.rreq_id, rreq_id);
    b.install_route(
        rep_b.responder,
        NODE_C,
        add_path_cost(rep_b.path_cost, 1),
        300,
    )
    .unwrap();
    b.forward().unwrap();
    let hop = b.next_hop(NODE_A, 300).unwrap();
    assert_eq!(hop, NODE_A);
    let air_ba = encode_cmd(&cmd_header(hop, NODE_B, 0x21), &pbody[..pn]);
    trace.push("B forwards RREP to A".to_string());

    // 5. A resolves the session and installs the route via B.
    let heard = decode(&air_ba).unwrap();
    let rep_a = decode_route_reply(heard.payload).unwrap().reply;
    assert!(a
        .note_discovery_reply(rep_a.rreq_id, rep_a.responder, NODE_B, 2, 400)
        .unwrap());
    // Stray replies resolve nothing and install nothing.
    assert!(!a
        .note_discovery_reply(0xFF, NODE_C, NODE_B, 2, 400)
        .unwrap());
    assert_eq!(a.next_hop(NODE_C, 400), Some(NODE_B));
    trace.push("A installs route to C via B".to_string());

    // 6. A routes a data frame to C through B.
    let data_req = NldeDataRequest {
        dst_addr: NODE_C,
        use_alias: false,
        alias_src: 0,
        alias_seq: 0,
        radius_param: 0,
        discover_route: DiscoverRoute::Suppress,
        generated_seq: 0x77,
        local_short_addr: NODE_A,
        max_depth: MAX_DEPTH,
        associated: true,
    };
    let data_header = build_data_header(&data_req).unwrap();
    let payload = [0xDE, 0xAD];
    let mut dout = vec![0u8; data_header.header_len() + payload.len()];
    let dn = data_header.encode_into(&payload, &mut dout).unwrap();
    dout.truncate(dn);
    let hop_a = a.next_hop(NODE_C, 500).unwrap();
    assert_eq!(hop_a, NODE_B);
    b.forward().unwrap();
    let hop_b = b.next_hop(NODE_C, 500).unwrap();
    assert_eq!(hop_b, NODE_C);
    let delivered = decode(&dout).unwrap();
    assert!(indication_for_local(
        delivered.header.dst_addr,
        NODE_C,
        false
    ));
    assert_eq!(delivered.payload, &[0xDE, 0xAD]);
    trace.push("A routes data to C via B; C accepts".to_string());
    trace.push(format!(
        "forwarded a={} b={} c={}",
        a.forwarded, b.forwarded, c.forwarded
    ));

    trace
}

// 05-3474-23-3645-01/02: discovery then a routed frame over three routers.
#[test]
fn route_discovery_then_routed_frame() {
    let trace = run();
    assert!(trace
        .iter()
        .any(|l| l.contains("A installs route to C via B")));
    assert!(trace.iter().any(|l| l.contains("C accepts")));
}

// Determinism: the same seed-free run replays identically.
#[test]
fn route_discovery_replays_identically() {
    assert_eq!(run(), run());
}

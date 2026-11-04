//! C6 router over ESP adapter: join → forward + host endpoint.
use rounddance_hal_esp::{EspAdapter, MockDriver, RouterDevice};
use rounddance_mac_sap::MacDataSap;
use rounddance_roles::{AgingPolicy, AppEndpoint, CommandError, RouterState, MAX_APP_PAYLOAD};

struct Lamp {
    id: u8,
    on: bool,
}
impl AppEndpoint for Lamp {
    fn endpoint_id(&self) -> u8 {
        self.id
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        payload: &[u8],
        response: &mut [u8],
    ) -> Result<usize, CommandError> {
        if payload == [0x01] {
            self.on = true;
            response[0] = 0x06;
            Ok(1)
        } else {
            Err(CommandError::BadCommand)
        }
    }
}

#[test]
fn c6_router_joins_forwards_and_serves_endpoint() {
    let mut adapter = EspAdapter::new(MockDriver::new());
    adapter.init().expect("init");
    assert_eq!(adapter.tx_queue_capacity(), 4);

    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);
    assert_eq!(router.state(), RouterState::Unjoined);
    router.begin_join().expect("begin");
    assert_eq!(router.join_done(true), RouterState::Active);

    router.admit_child(0x0001, 0x1122, false, 0).expect("admit");
    let id = router.next_hop(0x0002, 0);
    assert_eq!(id, None);
    router.install_route(0x0002, 0x0001, 1, 0).expect("route");
    assert_eq!(router.next_hop(0x0002, 1), Some(0x0001));

    router.forward(0x0002, &[0xaa, 0xbb]).expect("forward");
    assert_eq!(router.route_pending(), 1);
    assert_eq!(router.forwarded(), 1);

    let mut lamp = Lamp { id: 1, on: false };
    router.register_endpoint(&lamp).expect("register");
    router.deliver_to_endpoint(1, &[0x01]).expect("deliver");

    let mut out = [(0u16, [0u8; MAX_APP_PAYLOAD], 0usize); 8];
    let mut eps: [&mut Lamp; 1] = [&mut lamp];
    let (f, a) = router.tick(&mut eps, |e| e.endpoint_id(), &mut out, 2);
    assert_eq!((f, a), (1, 1));
    assert_eq!(out[0].0, 0x0002);
    assert!(lamp.on);
    assert_eq!(router.route_pending(), 0);
}

#[test]
fn board_s31_coordinator_and_c6_roles() {
    use rounddance_hal_esp::board::{BoardConfig, EspTarget};
    assert_eq!(EspTarget::S31.idf_target(), "esp32s31");
    assert_eq!(EspTarget::C6.idf_target(), "esp32c6");
    assert!(EspTarget::S31.supports_standalone_coordinator());
    assert!(EspTarget::C6.needs_xiao_c6_antenna_select());
    assert!(!EspTarget::S31.needs_xiao_c6_antenna_select());

    let s31 = BoardConfig::s31_coordinator([0x02; 6], 0x1a62, 15);
    assert_eq!(s31.target, EspTarget::S31);
    assert_eq!(s31.pan, 0x1a62);
    let c6r = BoardConfig::c6_router([0x03; 6], 0x1a62, 15);
    assert_eq!(c6r.target, EspTarget::C6);
}
/// The fw/rd-router child-service path, host-verified: the router's
/// MAC responder (`CoordAssoc` provisioned with the router short)
/// answers a child assoc-req with a router-pool short, and the
/// admitted sleepy child is held-for then served on poll — the exact
/// sequence the Active-phase pump runs on air.
#[test]
fn c6_router_child_assoc_and_poll_service() {
    use rounddance_hal_esp::mac_cmd::{build_assoc_req, parse_assoc_req, CoordAssoc};

    let mut adapter = EspAdapter::new(MockDriver::new());
    adapter.init().expect("init");

    // Router identity: short 0x0002, own EUI in wire order.
    let router_eui = [0xa0u8, 0xf2, 0x62, 0xff, 0xfe, 0x86, 0xe5, 0x10];
    let mut router_wire = router_eui;
    router_wire.reverse();
    let child_eui = [0xa0u8, 0xf2, 0x62, 0xff, 0xfe, 0x85, 0x97, 0xa4];
    let mut child_wire = child_eui;
    child_wire.reverse();

    let mut assoc = CoordAssoc::new();
    assoc.provision(0xC601, 0x0002, &router_wire);
    assoc.set_permit(true);
    assoc.allow(child_eui).expect("allow child");

    // Wrong destination short is not ours: no answer.
    let mut wrong = [0u8; 32];
    let wn = build_assoc_req(1, 0xC601, 0x0000, &child_wire, 0x8c, &mut wrong).unwrap();
    let wrong_req = parse_assoc_req(&wrong[..wn]).expect("parses");
    assert!(!assoc.assoc_pending());
    assert!(!assoc.on_assoc_req(&wrong_req));

    // Right destination: latch + answer with the router-pool short.
    let mut areq = [0u8; 32];
    let n = build_assoc_req(2, 0xC601, 0x0002, &child_wire, 0x8c, &mut areq).unwrap();
    let req = parse_assoc_req(&areq[..n]).expect("parses");
    assert!(assoc.on_assoc_req(&req));
    assert!(assoc.assoc_pending());
    let mut arsp = [0u8; 32];
    let rn = assoc.take_assoc_rsp(3, 0x0003, 0x00, &mut arsp).unwrap();
    assert!(rn > 0);

    // Child-table admission + hold → poll-serve lifecycle.
    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);
    router.begin_join().expect("begin");
    assert_eq!(router.join_done(true), RouterState::Active);
    router
        .admit_child(0x0003, u64::from_le_bytes(child_eui), true, 0)
        .expect("admit");
    router
        .hold_for_child(0x0003, &[0x01, 0x02], 10)
        .expect("hold");
    let served = router.serve_poll(0x0003, 20).expect("serve");
    assert!(served.is_some(), "held frame served on poll");
    let empty = router.serve_poll(0x0003, 30).expect("serve");
    assert!(empty.is_none(), "queue drained exactly once");
}
/// The fw/rd-router refuse branch, host-verified: an unjoined router
/// (failed uplink, `join_done(false)`) routes nothing, admits
/// nothing, holds nothing, and serves nothing — every duty refuses
/// with `BadState` until a completed join activates it.
#[test]
fn c6_router_refuses_until_joined() {
    use rounddance_roles::{RouterError, RouterState};
    let mut router = RouterDevice::new(AgingPolicy::default(), 60_000);
    assert_eq!(router.state(), RouterState::Unjoined);
    // Not even joining yet: all duties refuse.
    assert_eq!(router.forward(0x0000, &[0x01]), Err(RouterError::BadState));
    assert!(router.admit_child(0x0001, 0x1122, false, 0).is_err());
    assert!(router.hold_for_child(0x0001, &[0x01], 0).is_err());
    assert!(router.serve_poll(0x0001, 0).is_err());
    assert!(router.install_route(0x0000, 0x0000, 1, 0).is_err());
    // Failed uplink join: stays unjoined, still refuses.
    router.begin_join().expect("begin");
    assert_eq!(router.join_done(false), RouterState::Unjoined);
    assert_eq!(router.forward(0x0000, &[0x01]), Err(RouterError::BadState));
    // Successful uplink join: duties open.
    router.begin_join().expect("re-begin");
    assert_eq!(router.join_done(true), RouterState::Active);
    router
        .forward(0x0000, &[0x01])
        .expect("forward once active");
    assert_eq!(router.route_pending(), 1);
}

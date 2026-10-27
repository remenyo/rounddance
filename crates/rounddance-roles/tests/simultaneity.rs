//! Router+app simultaneity: the fairness rule under saturation.
//!
//! Requirement `05-3474-23-2325-ROLES-02` (MINTED-pending-confirm):
//! a router forwards transit traffic while serving its own
//! endpoints, and a flood on either side cannot starve the other
//! beyond one tick. Provenance: synthetic.

use rounddance_roles::{
    AppEndpoint, CommandError, EndpointTable, RouterApp, MAX_APP_PER_TICK, MAX_ROUTE_PER_TICK,
};

/// Minimal echo endpoint: responds with the bitwise complement.
struct EchoEndpoint {
    id: u8,
}

impl AppEndpoint for EchoEndpoint {
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
        if payload.len() > response.len() {
            return Err(CommandError::ResponseTooSmall);
        }
        for (i, byte) in payload.iter().enumerate() {
            response[i] = !byte;
        }
        Ok(payload.len())
    }
}

fn lookup(ep: &EchoEndpoint) -> u8 {
    ep.endpoint_id()
}

#[test]
fn endpoint_attach_rejects_bad_ids_2325_roles_01() {
    let mut table = EndpointTable::new();
    let bad_zero = EchoEndpoint { id: 0 };
    assert!(table.register(&bad_zero).is_err());
    let bad_ff = EchoEndpoint { id: 0xFF };
    assert!(table.register(&bad_ff).is_err());
    let mut good = EchoEndpoint { id: 7 };
    table.register(&good).unwrap();
    assert!(table.register(&good).is_err());
    assert_eq!(table.len(), 1);
    // Unknown endpoint delivery refused; oversize refused.
    assert!(table.deliver(9, &[0x01]).is_err());
    assert!(table.deliver(7, &[0x01; 200]).is_err());
    let _ = &mut good;
}

#[test]
fn router_serves_own_endpoint_while_forwarding_2325_roles_02() {
    let mut pair = RouterApp::new();
    let mut table = EndpointTable::new();
    let mut ep = EchoEndpoint { id: 3 };
    table.register(&ep).unwrap();
    // Transit traffic queued for forwarding.
    pair.queue_route(0x0004, &[0x11, 0x22]).unwrap();
    pair.queue_route(0x0005, &[0x33]).unwrap();
    // Local command for the hosted endpoint.
    table.deliver(3, &[0x0F, 0xF0]).unwrap();
    let mut out = [(0u16, [0u8; 128], 0usize); 8];
    let mut eps: [&mut EchoEndpoint; 1] = [&mut ep];
    let (forwarded, served) = pair.tick(&mut table, &mut eps, lookup, &mut out);
    assert_eq!((forwarded, served), (2, 1));
    assert_eq!(out[0].0, 0x0004);
    assert_eq!(&out[0].1[..out[0].2], &[0x11, 0x22]);
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[0xF0, 0x0F]);
    assert_eq!(pair.forwarded, 2);
    assert_eq!(pair.app_served, 1);
}

#[test]
fn fairness_budgets_hold_under_flood_2325_roles_02() {
    let mut pair = RouterApp::new();
    let mut table = EndpointTable::new();
    let mut ep = EchoEndpoint { id: 3 };
    table.register(&ep).unwrap();
    // Saturate the route side: more than one tick can take.
    for i in 0..MAX_ROUTE_PER_TICK {
        pair.queue_route(0x0100 + i as u16, &[i as u8]).unwrap();
    }
    // Route queue refuses beyond the per-tick bound (backpressure).
    assert!(pair.queue_route(0x0200, &[0xFF]).is_err());
    // Flood the app side: queue commands for the single endpoint;
    // only the latest pending command per endpoint is kept, so feed
    // one and verify the app slice still flows alongside a full
    // route queue.
    table.deliver(3, &[0x55]).unwrap();
    let mut out = [(0u16, [0u8; 128], 0usize); 8];
    let mut eps: [&mut EchoEndpoint; 1] = [&mut ep];
    let (forwarded, served) = pair.tick(&mut table, &mut eps, lookup, &mut out);
    assert_eq!(forwarded, MAX_ROUTE_PER_TICK);
    assert_eq!(served, 1);
    assert_eq!(pair.route_saturated_ticks, 1);
    // Next tick with an empty route queue still serves the app side.
    table.deliver(3, &[0xAA]).unwrap();
    let (forwarded, served) = pair.tick(&mut table, &mut eps, lookup, &mut out);
    assert_eq!((forwarded, served), (0, 1));
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[!0xAA]);
    assert_eq!(pair.app_served, 2);
    let _ = MAX_APP_PER_TICK;
}

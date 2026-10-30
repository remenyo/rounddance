//! Endpoint-table edge pins for hosted application endpoints.
//!
//! `simultaneity.rs` proves the router+app fairness rule; this file
//! pins the exact `EndpointError` variants of every refusal arm, the
//! `take_response` none-legs, the per-call dispatch budget, and the
//! reject-and-clear path for a declining endpoint implementation.
//! Provenance: synthetic.
//!
//! Requirement `05-3474-23-2325-ROLES-01` (MINTED-pending-confirm).

use rounddance_roles::endpoint::EndpointError;
use rounddance_roles::{
    AppEndpoint, CommandError, EndpointTable, MAX_APP_ENDPOINTS, MAX_APP_PAYLOAD,
};

/// Echo endpoint with a fixed id (complement response).
struct Echo {
    id: u8,
}

impl AppEndpoint for Echo {
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

/// Endpoint that declines every command.
struct RejectAll {
    id: u8,
}

impl AppEndpoint for RejectAll {
    fn endpoint_id(&self) -> u8 {
        self.id
    }
    fn profile_id(&self) -> u16 {
        0x0104
    }
    fn handle_command(
        &mut self,
        _payload: &[u8],
        _response: &mut [u8],
    ) -> Result<usize, CommandError> {
        Err(CommandError::Rejected)
    }
}

fn lookup_echo(ep: &Echo) -> u8 {
    ep.endpoint_id()
}

#[test]
fn register_pins_exact_error_variants() {
    let mut table = EndpointTable::new();
    assert!(table.is_empty());
    assert_eq!(
        table.register(&Echo { id: 0 }),
        Err(EndpointError::BadEndpointId)
    );
    assert_eq!(
        table.register(&Echo { id: 0xFF }),
        Err(EndpointError::BadEndpointId)
    );
    assert_eq!(table.register(&Echo { id: 1 }).map(|h| h.id()), Ok(1));
    assert_eq!(
        table.register(&Echo { id: 1 }),
        Err(EndpointError::DuplicateEndpoint)
    );
    assert_eq!(table.profile_id(1), Some(0x0104));
    assert_eq!(table.profile_id(2), None);
    // Fill to capacity, then refuse exactly one more.
    let mut eps: Vec<Echo> = (2..=MAX_APP_ENDPOINTS as u8)
        .map(|id| Echo { id })
        .collect();
    for ep in &eps {
        table.register(ep).unwrap();
    }
    assert_eq!(table.len(), MAX_APP_ENDPOINTS);
    assert!(!table.is_empty());
    assert_eq!(
        table.register(&Echo { id: 9 }),
        Err(EndpointError::TableFull)
    );
    let _ = &mut eps;
}

#[test]
fn deliver_pins_exact_error_variants() {
    let mut table = EndpointTable::new();
    table.register(&Echo { id: 7 }).unwrap();
    assert_eq!(
        table.deliver(9, &[0x01]),
        Err(EndpointError::NoSuchEndpoint)
    );
    assert_eq!(
        table.deliver(7, &[0x01; MAX_APP_PAYLOAD + 1]),
        Err(EndpointError::PayloadTooLarge)
    );
    // Boundary: exactly MAX_APP_PAYLOAD is admitted.
    let full = [0x55u8; MAX_APP_PAYLOAD];
    assert!(table.deliver(7, &full).is_ok());
}

#[test]
fn take_response_none_until_dispatched() {
    let mut table = EndpointTable::new();
    let mut ep = Echo { id: 3 };
    table.register(&ep).unwrap();
    // Unknown endpoint has no response slot at all.
    assert!(table.take_response(9).is_none());
    // Delivered but undispatched: pending, so no response yet.
    table.deliver(3, &[0x0F]).unwrap();
    assert!(table.take_response(3).is_none());
    // Dispatch through the implementation, then the echo lands.
    let mut eps: [&mut Echo; 1] = [&mut ep];
    assert_eq!(table.dispatch(&mut eps, lookup_echo, 1), 1);
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[!0x0F]);
    // Taking twice yields the cleared slot, not a replay.
    let (_, n2) = table.take_response(3).unwrap();
    assert_eq!(n2, 0);
}

#[test]
fn dispatch_budget_zero_holds_pending() {
    let mut table = EndpointTable::new();
    let mut ep = Echo { id: 3 };
    table.register(&ep).unwrap();
    table.deliver(3, &[0xAA]).unwrap();
    let mut eps: [&mut Echo; 1] = [&mut ep];
    // Zero budget dispatches nothing; the pending command survives.
    assert_eq!(table.dispatch(&mut eps, lookup_echo, 0), 0);
    assert!(table.take_response(3).is_none());
    assert_eq!(table.dispatch(&mut eps, lookup_echo, 1), 1);
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[!0xAA]);
}

#[test]
fn dispatch_rejected_command_clears_without_response() {
    let mut table = EndpointTable::new();
    let mut ep = RejectAll { id: 5 };
    table.register(&ep).unwrap();
    table.deliver(5, &[0x01, 0x02]).unwrap();
    let mut eps: [&mut RejectAll; 1] = [&mut ep];
    assert_eq!(table.dispatch(&mut eps, |e| e.endpoint_id(), 1), 1);
    // Declined: pending cleared, zero-length response (never stale).
    let (_, n) = table.take_response(5).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn dispatch_without_matching_impl_keeps_pending() {
    let mut table = EndpointTable::new();
    let mut ep = Echo { id: 3 };
    table.register(&ep).unwrap();
    table.deliver(3, &[0x77]).unwrap();
    // Lookup maps to an id with no live implementation: nothing
    // dispatched, pending preserved for a later tick.
    let mut eps: [&mut Echo; 1] = [&mut ep];
    assert_eq!(table.dispatch(&mut eps, |_| 0xFE, 4), 0);
    assert!(table.take_response(3).is_none());
    assert_eq!(table.dispatch(&mut eps, lookup_echo, 4), 1);
    let (resp, n) = table.take_response(3).unwrap();
    assert_eq!(&resp[..n], &[!0x77]);
}

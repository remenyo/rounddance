//! Host-side Direct commissioning over a scripted GATT client:
//! session establishment, form → steer → join → key update, the
//! finding-and-binding handoff, negative cases (bad key, request
//! timeout), and deterministic replay of the whole run.
//!
//! Requirement traceability: `20-27688-041-63-01` …
//! `20-27688-041-63-05` (sessions/keys), `20-27688-041-65-03`
//! (establishment), `20-27688-041-646-01` (counters),
//! `20-27688-041-76-01` (advertisements), `20-27688-041-772-01`
//! (service discipline + timeout), `20-27688-041-772-02`
//! (network-operation closure).

use rounddance_commission::{FinderInitiator, InstallCode};
use rounddance_direct::attr::decode_tlv;
use rounddance_direct::*;
use rounddance_sim::{Seed, SeededRng};

const JOINER_IEEE: u64 = 0x0200_0000_0000_0002;
const JOINER_NWK: u16 = 0x0001;

/// Scripted GATT-client driver over the Direct service model: it
/// speaks characteristic writes/reads to the session + commissioning
/// machines and records every outcome on a trace.
struct ScriptedGattClient {
    session: SessionMachine,
    direct: DirectCommission,
    adv: AdvPolicy,
    counters: BleCounters,
    rng: SeededRng,
    trace: Vec<String>,
}

impl ScriptedGattClient {
    fn new(seed: u64) -> Self {
        Self {
            session: SessionMachine::new(),
            direct: DirectCommission::new(),
            adv: AdvPolicy::new(60).unwrap(),
            counters: BleCounters::new(),
            rng: SeededRng::new(Seed(seed)),
            trace: Vec::new(),
        }
    }

    fn rng_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            let v = self.rng.next_u64().to_le_bytes();
            let take = (N - i).min(8);
            out[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
        out
    }

    fn log(&mut self, line: String) {
        self.trace.push(line);
    }

    /// Establish a session (counter send + establishment confirm).
    fn connect(&mut self, psk: PskKind, kind: SessionKind, countdown: u32) {
        let tx = self.counters.next_tx().unwrap();
        self.session.begin(psk, kind, countdown).unwrap();
        self.session.on_peer_activity();
        let got = self.session.on_established(true).unwrap();
        self.log(format!("connect:{got:?}:tx={tx}"));
    }

    /// Drain status notifications onto the trace as hex TLVs.
    fn drain_status(&mut self) {
        let mut notes = [StatusReport::success(StatusDomain::GENERAL); 4];
        let n = self.direct.take_notifications(&mut notes);
        for r in notes.iter().take(n) {
            let mut buf = [0u8; 8];
            let m = r.encode_into(&mut buf).unwrap();
            let (tlv, _) = decode_tlv(&buf[..m]).unwrap();
            assert_eq!(tlv.tag, 0x0E);
            self.log(format!("status:{:02x}{:02x}", r.domain, r.code));
        }
    }

    fn form(&mut self, admin: Option<[u8; 16]>) {
        let network_key = self.rng_bytes::<16>();
        let params = NetworkParams {
            ext_pan: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
            pan_id: 0x1A2B,
            channel: 15,
            nwk_addr: 0x0000,
            device_type: DeviceType::Coordinator,
            network_key,
        };
        self.direct.submit(DirectOp::Form).unwrap();
        let ev = self.direct.complete_form(params, admin).unwrap();
        self.log(format!("form:{ev:?}:key={}", hex(&network_key)));
        self.adv.mark_provisioned();
        self.session.mark_provisioned();
        self.drain_status();
        // Advertisement refreshes on state change (76-01).
        let adv = AdvExtension {
            tunnel_supported: false,
            permit_join: false,
            pan_id: 0x1A2B,
            nwk_addr: 0x0000,
        };
        let mut buf = [0u8; ADV_RECORD_LEN];
        adv.encode_into(&mut buf).unwrap();
        self.log(format!("adv:{}", hex(&buf)));
    }

    fn permit(&mut self, duration_s: u32) {
        self.direct.submit(DirectOp::PermitJoining).unwrap();
        let ev = self.direct.complete_permit(duration_s).unwrap();
        self.log(format!("permit:{duration_s}:{ev:?}"));
        self.drain_status();
    }

    fn install_code(&mut self) -> [u8; 10] {
        let payload = self.rng_bytes::<8>();
        let mut out = [0u8; 10];
        let n = InstallCode::with_crc(&payload, &mut out).unwrap();
        assert_eq!(n, 10);
        out
    }

    fn join(&mut self, code: &[u8]) {
        self.log(format!("join-code:{}", hex(code)));
        self.direct.submit(DirectOp::Join).unwrap();
        let ev = self
            .direct
            .complete_join(
                JoinMethod::MacAssociation,
                JOINER_IEEE,
                JOINER_NWK,
                Some(code),
                None,
            )
            .unwrap();
        self.log(format!("join:{ev:?}"));
        self.drain_status();
        // Finding-and-binding handoff into the classical machines.
        if let DirectEvent::FindingHandoff(h) = ev {
            let mut target = rounddance_commission::FinderTarget::new();
            target.start(true, 60).unwrap();
            let mut init = FinderInitiator::new();
            init.begin(true);
            init.note_answer(h.nwk_addr, 1);
            init.finish_queries();
            self.log(format!(
                "handoff:initiator={}:target={:?}",
                h.initiator,
                target.state()
            ));
        }
    }

    fn key_update(&mut self, nonce: u32) {
        let ieee = JOINER_IEEE.to_le_bytes();
        self.direct.submit(DirectOp::UpdateKey).unwrap();
        let ev = self
            .direct
            .complete_key_update(ieee, nonce, LinkKeyFlags(0b11))
            .unwrap();
        self.log(format!("key-update:{nonce}:{ev:?}"));
        self.drain_status();
    }

    fn tick(&mut self, secs: u32) {
        for _ in 0..secs {
            let _ = self.session.tick_1s();
            self.direct.tick_1s();
            self.adv.tick_1s(false);
        }
        self.log(format!(
            "tick:{secs}:permit={}",
            self.direct.permit_remaining()
        ));
    }
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xF) as usize] as char);
    }
    s
}

/// One full Direct commissioning: connect → form → steer →
/// join → key update → finding handoff.
fn full_run(seed: u64) -> Vec<String> {
    let mut g = ScriptedGattClient::new(seed);
    g.connect(PskKind::InstallCode, SessionKind::Provisioning, 0);
    g.form(None);
    g.permit(180);
    let code = g.install_code();
    g.join(&code);
    g.key_update(42);
    g.tick(5);
    g.trace
}

#[test]
fn direct_full_commissioning() {
    let trace = full_run(0xD1EC7);
    assert!(trace.iter().any(|l| l.starts_with("form:")));
    assert!(trace.iter().any(|l| l.starts_with("permit:180")));
    assert!(trace.iter().any(|l| l.starts_with("join:")));
    assert!(trace.iter().any(|l| l.starts_with("key-update:42")));
    assert!(trace.iter().any(|l| l.starts_with("handoff:")));
    // Every operation reported success on the status characteristic.
    let failures = trace
        .iter()
        .filter(|l| l.starts_with("status:") && !l.ends_with("00"));
    assert_eq!(failures.count(), 0);
}

#[test]
fn direct_commissioning_replays_deterministically() {
    assert_eq!(full_run(0xBEEF), full_run(0xBEEF));
    assert_ne!(full_run(0xBEEF), full_run(0xCAFE));
}

#[test]
fn direct_bad_key_fails_cleanly() {
    let mut g = ScriptedGattClient::new(7);
    g.connect(PskKind::InstallCode, SessionKind::Provisioning, 0);
    g.form(None);
    g.permit(60);
    let mut code = g.install_code();
    code[9] ^= 0xFF;
    g.direct.submit(DirectOp::Join).unwrap();
    assert_eq!(
        g.direct.complete_join(
            JoinMethod::MacAssociation,
            JOINER_IEEE,
            JOINER_NWK,
            Some(&code),
            None
        ),
        Err(DirectError::BadParams)
    );
    g.drain_status();
    assert!(g.trace.iter().any(|l| *l == "status:0201"));
    // The device still holds its formed network and the machine
    // serves the next request (rejection completed, not wedged).
    assert!(g.direct.joined());
    assert_eq!(g.direct.state(), DirectState::Idle);
}

#[test]
fn direct_leave_returns_to_provision() {
    let mut g = ScriptedGattClient::new(11);
    g.connect(PskKind::InstallCode, SessionKind::Provisioning, 0);
    g.form(None);
    g.direct.submit(DirectOp::Leave).unwrap();
    assert_eq!(
        g.direct.complete_leave().unwrap(),
        DirectEvent::NetworkErased
    );
    assert!(!g.direct.joined());
    g.drain_status();
    assert!(g.trace.iter().any(|l| *l == "status:0400"));
    // Leave returns the advertiser to open-to-provision.
    g.adv.mark_unprovisioned();
    assert!(g.adv.extension_visible());
}

#[test]
fn direct_request_timeout_fails_cleanly() {
    let mut g = ScriptedGattClient::new(9);
    g.connect(PskKind::InstallCode, SessionKind::Provisioning, 0);
    g.form(None);
    // Submit but never complete: the 3-second timeout fires.
    g.direct.submit(DirectOp::PermitJoining).unwrap();
    g.tick(2);
    assert_eq!(g.direct.state(), DirectState::Busy);
    g.tick(1);
    assert_eq!(g.direct.state(), DirectState::Failed);
    g.drain_status();
    assert!(g.trace.iter().any(|l| *l == "status:0301"));
    g.direct.recover();
    // The machine serves the next request after recovery.
    g.permit(30);
    assert!(g.trace.iter().any(|l| *l == "status:0300"));
}

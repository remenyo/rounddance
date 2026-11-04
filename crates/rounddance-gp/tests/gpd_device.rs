//! GPD device leg: commission → data decodes via the proxy/sink codec.
use rounddance_gp::frame::FrameType;
use rounddance_gp::{GpdDevice, Gpdf, GPD_TOGGLE_CMD};

#[test]
fn gpd_commission_then_toggle_roundtrip() {
    let mut gpd = GpdDevice::new_srcid(0x1234_5678);
    let mut buf = [0u8; 128];
    let n = gpd.build_commissioning(&mut buf).expect("commission");
    assert!(n > 0);
    let (dec, _) = Gpdf::decode(&buf[..n]).expect("decode commission");
    assert!(dec.fc.auto_commissioning);
    assert_eq!(dec.fc.frame_type, FrameType::Data);

    // Data before commissioned must refuse.
    let mut fresh = GpdDevice::new_srcid(0x1234_5678);
    assert!(fresh.build_data(GPD_TOGGLE_CMD, &[0x01], &mut buf).is_err());

    gpd.mark_commissioned();
    let n2 = gpd
        .build_data(GPD_TOGGLE_CMD, &[0x01], &mut buf)
        .expect("data");
    let (dec2, _) = Gpdf::decode(&buf[..n2]).expect("decode data");
    assert!(!dec2.fc.auto_commissioning);
    assert_eq!(gpd.data_sent, 1);
}

#[test]
fn gpd_bidir_success_closes_commissioning() {
    use rounddance_gp::{GpdState, CMD_SUCCESS};
    let mut gpd = GpdDevice::new_srcid(0x1234_5678);
    let mut buf = [0u8; 128];
    // Success before any commissioning exchange must refuse.
    assert!(gpd.build_success(&mut buf).is_err());
    let _ = gpd.build_commissioning(&mut buf).expect("commission");
    assert_eq!(gpd.state(), GpdState::Commissioning);
    let n = gpd.build_success(&mut buf).expect("success");
    let (dec, _) = Gpdf::decode(&buf[..n]).expect("decode success");
    match dec.body {
        rounddance_gp::GpdfBody::Gp { command, payload } => {
            assert_eq!(command, CMD_SUCCESS);
            assert!(payload.is_empty());
        }
        _ => panic!("success must be a GP body"),
    }
    assert_eq!(gpd.state(), GpdState::Commissioned);
}

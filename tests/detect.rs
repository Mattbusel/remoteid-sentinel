//! End-to-end: generate real scenarios with `remoteid-scenario`, feed the
//! already-decoded frames into the receive-only analyzer, and check it flags
//! the flood and names the genuine track, and does not cry flood on a clean
//! baseline. Nothing here transmits; the frames are bytes a sensor would have
//! decoded.

use remoteid::{Observation, Tracker, TrackerConfig, Transmitter};
use remoteid_scenario::{generate, EmittedFrame, Scenario, ScenarioKind};
use remoteid_sentinel::{FieldAssessment, FloodLevel};

/// A generated frame flattened to the bytes a receiver decodes, so an
/// `Observation` can borrow the payload.
struct Encoded {
    transmitter: Transmitter,
    counter: u8,
    bytes: [u8; 25],
    rssi_dbm: i8,
    now_ms: u64,
}

fn encode_all(frames: &[EmittedFrame]) -> Vec<Encoded> {
    frames
        .iter()
        .map(|f| Encoded {
            transmitter: f.transmitter,
            counter: f.counter,
            bytes: f.message.encode().expect("scenario frames encode"),
            rssi_dbm: f.rssi_dbm,
            now_ms: f.time_us / 1000,
        })
        .collect()
}

fn now_ms(encoded: &[Encoded]) -> u64 {
    encoded.iter().map(|e| e.now_ms).max().unwrap_or(0) + 1
}

fn observations(encoded: &[Encoded]) -> impl Iterator<Item = (Transmitter, Observation<'_>)> {
    encoded.iter().map(|e| {
        let obs = Observation::new(
            remoteid::Transport::Bluetooth4,
            Some(e.counter),
            &e.bytes,
            e.now_ms,
        )
        .with_rssi(e.rssi_dbm);
        (e.transmitter, obs)
    })
}

#[test]
fn flood_is_flagged_and_the_genuine_track_is_named() {
    let scenario = Scenario::new(ScenarioKind::Flood, 50);
    let genuine_serial = scenario.genuine.serial.clone();
    let encoded = encode_all(&generate(&scenario));
    let now = now_ms(&encoded);

    let field = FieldAssessment::from_observations(observations(&encoded), now);

    assert!(
        field.flood.is_flood(),
        "flood of 50 fakes should read as flooded, got {:?} (confidence {:.2})",
        field.flood.level,
        field.flood.confidence
    );

    let real = field
        .most_likely_real
        .expect("the one genuine track should be named");
    assert_eq!(
        real.uas_id.as_deref(),
        Some(genuine_serial.as_str()),
        "the named real track should be the embedded genuine drone; reasons: {:?}",
        real.genuine_reasons
    );
    assert!(
        !real.genuine_reasons.is_empty(),
        "the genuine choice should come with reasons"
    );
    assert!(
        real.real_score > 0.5,
        "the genuine track should outscore the flood, got {:.2}",
        real.real_score
    );
}

#[test]
fn clean_baseline_raises_no_false_flood() {
    let scenario = Scenario::new(ScenarioKind::Clean, 3);
    let encoded = encode_all(&generate(&scenario));
    let now = now_ms(&encoded);

    let field = FieldAssessment::from_observations(observations(&encoded), now);

    assert_eq!(
        field.flood.level,
        FloodLevel::Clear,
        "a handful of honest drones must not read as a flood; confidence {:.2}, tracks {:?}",
        field.flood.confidence,
        field
            .tracks
            .iter()
            .map(|t| (t.uas_id.clone(), t.fake_signals))
            .collect::<Vec<_>>()
    );
    // Every honest track stays eligible as a real drone.
    assert!(
        field.most_likely_real.is_some(),
        "a clean field still has a most-likely-real track"
    );
    for t in &field.tracks {
        assert!(
            t.fake_signals.is_empty(),
            "honest track {:?} should carry no fake signals, got {:?}",
            t.uas_id,
            t.fake_signals
        );
    }
}

#[test]
fn from_tracker_path_agrees_on_a_clean_field() {
    let scenario = Scenario::new(ScenarioKind::Clean, 3);
    let encoded = encode_all(&generate(&scenario));
    let now = now_ms(&encoded);

    // Build a tracker exactly as a sensor would, then analyze its final state.
    let mut tracker = Tracker::new(TrackerConfig::default());
    for (tx, obs) in observations(&encoded) {
        tracker.observe(tx, &obs);
    }
    let field = FieldAssessment::from_tracker(&tracker, now);

    assert_eq!(field.flood.level, FloodLevel::Clear);
    assert_eq!(field.tracks.len(), 3);
}

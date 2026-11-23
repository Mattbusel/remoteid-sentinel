//! End-to-end protected-zone and loiter checks over decoded tracks.
//!
//! The tracks are built as spec-compliant Remote ID message streams: a flood
//! scenario from `remoteid-scenario` (its embedded genuine track flies a known
//! straight line), and a circular orbit constructed here from a cited geometry.
//! Every frame is encoded and decoded through the `remoteid` library, so the
//! analyzer sees the same bytes a sensor would. Nothing here transmits.

use remoteid::{
    BasicId, IdType, Location, Message, Observation, Status, Transmitter, Transport, UaType,
};
use remoteid_scenario::{generate, EmittedFrame, GenuineTrack, Scenario, ScenarioKind};
use remoteid_sentinel::{
    loiter_check, zone_breach, LoiterConfig, ProtectedZone, TrackPath, ZoneConfig, ZoneStatus,
};

/// A flood scenario whose single genuine track starts at a known point and
/// flies due east at a known speed, so we can place a zone on its path.
const START_LAT: f64 = 40.7128;
const START_LON: f64 = -74.0060;
const SPEED_MPS: f32 = 12.0;

/// Metres per degree of latitude on the mean sphere (matches the library's
/// haversine); used only to place zones at computed offsets.
fn m_per_deg() -> f64 {
    remoteid::geo::EARTH_RADIUS_M * std::f64::consts::PI / 180.0
}

/// A generated frame flattened to the bytes a receiver decodes.
struct Encoded {
    transmitter: Transmitter,
    counter: u8,
    bytes: [u8; 25],
    now_ms: u64,
}

fn encode_all(frames: &[EmittedFrame]) -> Vec<Encoded> {
    frames
        .iter()
        .map(|f| Encoded {
            transmitter: f.transmitter,
            counter: f.counter,
            bytes: f.message.encode().expect("scenario frames encode"),
            now_ms: f.time_us / 1000,
        })
        .collect()
}

fn observations(encoded: &[Encoded]) -> impl Iterator<Item = (Transmitter, Observation<'_>)> {
    encoded.iter().map(|e| {
        let obs = Observation::new(Transport::Bluetooth4, Some(e.counter), &e.bytes, e.now_ms);
        (e.transmitter, obs)
    })
}

/// Build the flood scenario and return the decoded path of its genuine track.
fn genuine_path() -> TrackPath {
    let mut scenario = Scenario::new(ScenarioKind::Flood, 20);
    scenario.genuine = GenuineTrack {
        serial: "1581CREAL7A4F2C91".to_string(),
        start_lat: START_LAT,
        start_lon: START_LON,
        heading_deg: 90.0, // due east
        speed_mps: SPEED_MPS,
        rssi_dbm: -58,
    };
    let genuine_serial = scenario.genuine.serial.clone();
    let encoded = encode_all(&generate(&scenario));
    let paths = TrackPath::from_observations(observations(&encoded));
    paths
        .into_iter()
        .find(|p| p.uas_id.as_deref() == Some(genuine_serial.as_str()))
        .expect("the genuine track decodes into a path")
}

#[test]
fn drone_inside_the_zone_is_a_breach() {
    let path = genuine_path();
    let last = *path.fixes.last().expect("the track has fixes");

    // A 60 m protected circle centred on the track's final fix: the drone is
    // inside it, so distance to the boundary is zero.
    let zone = ProtectedZone::circle(last.lat, last.lon, 60.0);
    let alert = zone_breach(&path, &zone, &ZoneConfig::default()).expect("a fix to judge");

    assert_eq!(
        alert.status,
        ZoneStatus::Inside,
        "a drone at the zone centre must read as inside; distance {:.1} m",
        alert.distance_m
    );
    assert_eq!(alert.distance_m, 0.0);
    assert!(alert.is_breach());
}

#[test]
fn drone_approaching_the_zone_is_flagged_with_closing_speed() {
    let path = genuine_path();
    let last = *path.fixes.last().expect("the track has fixes");

    // A 50 m circle 300 m due east of the final fix: the drone is outside but
    // flying straight at it at ~12 m/s. Place the centre 300 m east.
    let coslat = last.lat.to_radians().cos();
    let dlon = 300.0 / (m_per_deg() * coslat);
    let zone = ProtectedZone::circle(last.lat, last.lon + dlon, 50.0);

    let alert = zone_breach(&path, &zone, &ZoneConfig::default()).expect("a fix to judge");

    assert_eq!(
        alert.status,
        ZoneStatus::Approaching,
        "a drone closing on the zone must read as approaching; distance {:.1} m, closing {:.2} m/s",
        alert.distance_m,
        alert.closing_speed_mps
    );
    // Boundary is ~300 - 50 = 250 m away.
    assert!(
        (alert.distance_m - 250.0).abs() < 20.0,
        "distance to boundary {:.1} m",
        alert.distance_m
    );
    // Closing speed is the ground speed, ~12 m/s, since it flies straight in.
    assert!(
        (alert.closing_speed_mps - SPEED_MPS as f64).abs() < 1.5,
        "closing speed {:.2} m/s",
        alert.closing_speed_mps
    );
    // Time to boundary ~250 / 12 ~ 21 s.
    let eta = alert.eta_s.expect("an approaching track has an ETA");
    assert!((eta - 21.0).abs() < 4.0, "eta {:.1} s", eta);
    assert!(alert.is_breach());
}

#[test]
fn drone_outside_and_not_closing_is_clear() {
    let path = genuine_path();
    let first = path.fixes[0];

    // A small circle 2 km due *south* of the start: the eastbound drone never
    // nears it, so nothing fires.
    let dlat = 2000.0 / m_per_deg();
    let zone = ProtectedZone::circle(first.lat - dlat, first.lon, 100.0);
    let alert = zone_breach(&path, &zone, &ZoneConfig::default()).expect("a fix to judge");

    assert_eq!(
        alert.status,
        ZoneStatus::Clear,
        "distance {:.1}",
        alert.distance_m
    );
    assert!(!alert.is_breach());
}

/// Build a straight transit as spec-compliant frames: `points` fixes along a
/// due-east line at `speed_mps`, one every `step_ms`.
fn line_frames(
    start_lat: f64,
    start_lon: f64,
    speed_mps: f64,
    points: usize,
    step_ms: u64,
    serial: &str,
    tx: Transmitter,
) -> Vec<Encoded> {
    let mpd = m_per_deg();
    let coslat = start_lat.to_radians().cos();
    let mut out = Vec::new();
    for k in 0..points {
        let now_ms = k as u64 * step_ms;
        let east_m = speed_mps * (now_ms as f64 / 1000.0);
        let lon = start_lon + east_m / (mpd * coslat);
        let basic = Message::BasicId(
            BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, serial)
                .expect("serial fits"),
        );
        let loc = Message::Location(Location {
            status: Status::Airborne,
            latitude: start_lat,
            longitude: lon,
            altitude_geo: Some(60.0),
            height: Some(60.0),
            direction: Some(90.0),
            speed_horizontal: Some(speed_mps as f32),
            speed_vertical: Some(0.0),
            ..Location::default()
        });
        for message in [basic, loc] {
            let bytes = message.encode().expect("message encodes");
            out.push(Encoded {
                transmitter: tx,
                counter: (k & 0xFF) as u8,
                bytes,
                now_ms,
            });
        }
    }
    out
}

#[test]
fn straight_transit_does_not_read_as_loitering() {
    // A drone crossing the area at 12 m/s for three minutes: same time budget
    // as a loiter, but it never stays inside a small radius, so it must not be
    // flagged. The discriminator is the radius, not the duration.
    let tx = Transmitter::Ble([0x02, 0x00, 0x99, 0x88, 0x77, 0x66]);
    let encoded = line_frames(40.7128, -74.0060, 12.0, 36, 5_000, "1581CTRANSIT00001", tx);
    let paths = TrackPath::from_observations(observations(&encoded));
    let path = paths.into_iter().next().expect("one transit track");

    // Same two-minute, 60 m window that flags the orbit below.
    let cfg = LoiterConfig::new(60.0, 120_000, 5);
    assert!(
        loiter_check(&path, &cfg).is_none(),
        "a straight transit must not be flagged as loitering"
    );
}

/// Build a circular orbit as spec-compliant frames: `points` fixes evenly
/// around a circle of `radius_m` about `(clat, clon)`, one every `step_ms`.
fn orbit_frames(
    clat: f64,
    clon: f64,
    radius_m: f64,
    points: usize,
    step_ms: u64,
    serial: &str,
    tx: Transmitter,
) -> Vec<Encoded> {
    let mpd = m_per_deg();
    let coslat = clat.to_radians().cos();
    let mut out = Vec::new();
    for k in 0..points {
        let theta = 2.0 * std::f64::consts::PI * (k as f64) / (points as f64);
        // North/East offsets on the circle, converted to lat/lon.
        let north_m = radius_m * theta.cos();
        let east_m = radius_m * theta.sin();
        let lat = clat + north_m / mpd;
        let lon = clon + east_m / (mpd * coslat);
        let now_ms = k as u64 * step_ms;

        let basic = Message::BasicId(
            BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, serial)
                .expect("serial fits"),
        );
        let loc = Message::Location(Location {
            status: Status::Airborne,
            latitude: lat,
            longitude: lon,
            altitude_geo: Some(60.0),
            height: Some(60.0),
            direction: Some(((theta.to_degrees() + 90.0) % 360.0) as f32),
            speed_horizontal: Some(5.0),
            speed_vertical: Some(0.0),
            ..Location::default()
        });
        for message in [basic, loc] {
            // Normalise through the wire encoding so the decoded fix equals
            // what a receiver sees.
            let bytes = message.encode().expect("message encodes");
            out.push(Encoded {
                transmitter: tx,
                counter: (k & 0xFF) as u8,
                bytes,
                now_ms,
            });
        }
    }
    out
}

#[test]
fn circling_drone_is_flagged_as_loitering() {
    // A real surveillance pattern: one drone orbiting a 40 m circle over a
    // facility, a fix every 5 s for 3 minutes (36 points).
    let clat = 40.7128;
    let clon = -74.0060;
    let radius_m = 40.0;
    let tx = Transmitter::Ble([0x02, 0x00, 0x12, 0x34, 0x56, 0x78]);
    let encoded = orbit_frames(clat, clon, radius_m, 36, 5_000, "1581CORBIT0000001", tx);
    let paths = TrackPath::from_observations(observations(&encoded));
    let path = paths.into_iter().next().expect("one orbiting track");

    // two-minute hold, 60 m radius
    let cfg = LoiterConfig::new(60.0, 120_000, 5);
    let alert = loiter_check(&path, &cfg).expect("the orbit should be flagged as loitering");

    // The recovered centre is the orbit centre, within a few metres.
    let off = remoteid::geo::distance_m(alert.center.0, alert.center.1, clat, clon);
    assert!(off < 8.0, "recovered centre is {:.1} m off", off);
    // The measured orbit radius matches the 40 m circle (quantized to the grid).
    assert!(
        (alert.radius_m - radius_m).abs() < 5.0,
        "measured orbit radius {:.1} m",
        alert.radius_m
    );
    // It held for at least two minutes.
    assert!(
        alert.duration_ms >= 120_000,
        "loiter duration {} ms",
        alert.duration_ms
    );
    assert!(alert.fix_count >= 25, "fix count {}", alert.fix_count);
}

#[test]
fn hovering_drone_is_flagged_as_loitering() {
    // A hover is a zero-radius orbit: the same point held for three minutes.
    let clat = 51.5074;
    let clon = -0.1278;
    let tx = Transmitter::Ble([0x02, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
    let encoded = orbit_frames(clat, clon, 0.0, 36, 5_000, "1581CHOVER0000001", tx);
    let paths = TrackPath::from_observations(observations(&encoded));
    let path = paths.into_iter().next().expect("one hovering track");

    let alert = loiter_check(&path, &LoiterConfig::default())
        .expect("a three-minute hover should be flagged");
    assert!(alert.radius_m < 5.0, "hover radius {:.1} m", alert.radius_m);
    assert!(alert.duration_ms >= 120_000);
}

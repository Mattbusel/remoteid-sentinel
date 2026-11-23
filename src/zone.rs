//! Protected-zone breach and loitering analysis over already-decoded tracks.
//!
//! The field analyzer in [`crate::analyze`] answers "is this airspace flooded,
//! and which track is the one real drone?" This module answers the next two
//! questions a site operator actually asks about that real drone:
//!
//! 1. *Is it a threat to my site, right now?* Given a protected area (a circle
//!    or a polygon), [`zone_breach`] reports whether a tracked drone is
//!    **inside** the zone or **approaching** it, with the distance to the
//!    boundary, the closing speed, and a time-to-boundary estimate. That is
//!    "a drone breached the perimeter," not "drones exist."
//! 2. *Is it watching me?* [`loiter_check`] flags a drone that has been
//!    circling or hovering within a small radius of one point for longer than
//!    a threshold: "this track has been orbiting the facility for N minutes."
//!
//! Everything here is receive-only geometry over positions a sensor already
//! decoded. It opens no radio and emits nothing. Feed it the tracks you trust
//! (for example the ones [`crate::FieldAssessment`] did not flag as part of a
//! flood) so the alert is about a real aircraft, not a spoofed one.
//!
//! # Geometry
//!
//! Great-circle distances use [`remoteid::geo::distance_m`] (haversine on the
//! mean sphere). Point-in-polygon uses the standard even-odd ray cast in
//! latitude/longitude; distance from a point to a polygon edge is computed in
//! a local east/north metre frame centred on the query point. Both are
//! accurate for the site-scale zones (perimeters of metres to a few
//! kilometres) this is built for, and both assume a zone that does not cross a
//! pole or the +-180 degree meridian.

use std::collections::HashMap;

use remoteid::geo::{distance_m, EARTH_RADIUS_M};
use remoteid::{Frame, Message, Observation, Transmitter};

/// Metres per degree of latitude on the mean sphere, consistent with
/// [`remoteid::geo::distance_m`].
fn meters_per_deg_lat() -> f64 {
    EARTH_RADIUS_M * core::f64::consts::PI / 180.0
}

/// One decoded position fix on a track.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    /// Observation time, in the sensor's millisecond clock.
    pub t_ms: u64,
    /// Latitude, degrees.
    pub lat: f64,
    /// Longitude, degrees.
    pub lon: f64,
}

/// The decoded position history of one track, keyed by its on-air source.
///
/// This is the receive-only view the zone and loiter checks work on: a series
/// of fixes plus the latest reported speed and course. Build it from a decoded
/// observation stream with [`TrackPath::from_observations`].
#[derive(Debug, Clone)]
pub struct TrackPath {
    /// The on-air source this track is keyed by.
    pub transmitter: Transmitter,
    /// The primary UAS ID shown for the track, if any.
    pub uas_id: Option<String>,
    /// Decoded position fixes, oldest first.
    pub fixes: Vec<Fix>,
    /// Latest reported ground speed, m/s, if the track carried one.
    pub last_speed_mps: Option<f32>,
    /// Latest reported course over ground, degrees from north, if any.
    pub last_course_deg: Option<f32>,
}

impl TrackPath {
    /// Decode a stream of already-observed frames into one [`TrackPath`] per
    /// source address.
    ///
    /// Each `(transmitter, observation)` is a frame the sensor already
    /// received and decoded. Location messages become [`Fix`]es tagged with
    /// the observation time; the first non-empty Basic ID becomes the track's
    /// `uas_id`. Nothing here transmits.
    pub fn from_observations<'a, I>(obs: I) -> Vec<TrackPath>
    where
        I: IntoIterator<Item = (Transmitter, Observation<'a>)>,
    {
        struct Acc {
            uas_id: Option<String>,
            fixes: Vec<Fix>,
            last_speed: Option<f32>,
            last_course: Option<f32>,
            last_t: u64,
            seen: bool,
        }

        let mut map: HashMap<Transmitter, Acc> = HashMap::new();
        let mut order: Vec<Transmitter> = Vec::new();

        for (tx, o) in obs {
            let acc = map.entry(tx).or_insert_with(|| {
                order.push(tx);
                Acc {
                    uas_id: None,
                    fixes: Vec::new(),
                    last_speed: None,
                    last_course: None,
                    last_t: 0,
                    seen: false,
                }
            });
            if let Ok(frame) = Frame::decode(o.payload) {
                frame.for_each_message(|m| match m {
                    Message::BasicId(b) => {
                        if acc.uas_id.is_none() {
                            if let Some(id) = b.uas_id_str().filter(|s| !s.is_empty()) {
                                acc.uas_id = Some(id.to_string());
                            }
                        }
                    }
                    Message::Location(loc) => {
                        if let Some((lat, lon)) = loc.position() {
                            acc.fixes.push(Fix {
                                t_ms: o.now_ms,
                                lat,
                                lon,
                            });
                            if !acc.seen || o.now_ms >= acc.last_t {
                                acc.seen = true;
                                acc.last_t = o.now_ms;
                                acc.last_speed = loc.speed_horizontal;
                                acc.last_course = loc.direction;
                            }
                        }
                    }
                    _ => {}
                });
            }
        }

        order
            .into_iter()
            .filter_map(|tx| map.remove(&tx).map(|acc| (tx, acc)))
            .map(|(tx, acc)| {
                let mut fixes = acc.fixes;
                fixes.sort_by_key(|f| f.t_ms);
                TrackPath {
                    transmitter: tx,
                    uas_id: acc.uas_id,
                    fixes,
                    last_speed_mps: acc.last_speed,
                    last_course_deg: acc.last_course,
                }
            })
            .collect()
    }
}

/// A protected area a site wants kept clear of drones.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectedZone {
    /// A circle: everything within `radius_m` metres of the centre.
    Circle {
        /// Centre latitude, degrees.
        lat: f64,
        /// Centre longitude, degrees.
        lon: f64,
        /// Radius, metres.
        radius_m: f64,
    },
    /// A polygon given as `(latitude, longitude)` vertices in order. The ring
    /// is closed automatically; three or more vertices are required.
    Polygon {
        /// The ordered `(lat, lon)` vertices.
        vertices: Vec<(f64, f64)>,
    },
}

impl ProtectedZone {
    /// A circular protected zone.
    pub fn circle(lat: f64, lon: f64, radius_m: f64) -> ProtectedZone {
        ProtectedZone::Circle { lat, lon, radius_m }
    }

    /// A polygonal protected zone from ordered `(lat, lon)` vertices.
    pub fn polygon(vertices: Vec<(f64, f64)>) -> ProtectedZone {
        ProtectedZone::Polygon { vertices }
    }

    /// Whether a point lies inside the zone (on the boundary counts as inside).
    pub fn contains(&self, lat: f64, lon: f64) -> bool {
        match self {
            ProtectedZone::Circle {
                lat: clat,
                lon: clon,
                radius_m,
            } => distance_m(lat, lon, *clat, *clon) <= *radius_m,
            ProtectedZone::Polygon { vertices } => point_in_polygon(lat, lon, vertices),
        }
    }

    /// Distance in metres from a point to the zone boundary, or `0.0` when the
    /// point is inside the zone.
    pub fn distance_to_boundary_m(&self, lat: f64, lon: f64) -> f64 {
        match self {
            ProtectedZone::Circle {
                lat: clat,
                lon: clon,
                radius_m,
            } => (distance_m(lat, lon, *clat, *clon) - *radius_m).max(0.0),
            ProtectedZone::Polygon { vertices } => {
                if point_in_polygon(lat, lon, vertices) {
                    0.0
                } else {
                    distance_to_polygon_m(lat, lon, vertices)
                }
            }
        }
    }
}

/// Even-odd ray cast: is `(lat, lon)` inside the polygon ring?
fn point_in_polygon(lat: f64, lon: f64, verts: &[(f64, f64)]) -> bool {
    let n = verts.len();
    if n < 3 {
        return false;
    }
    let mut inside = false;
    let mut j = n - 1;
    for i in 0..n {
        let (yi, xi) = verts[i];
        let (yj, xj) = verts[j];
        let straddles = (yi > lat) != (yj > lat);
        if straddles {
            let x_cross = (xj - xi) * (lat - yi) / (yj - yi) + xi;
            if lon < x_cross {
                inside = !inside;
            }
        }
        j = i;
    }
    inside
}

/// Shortest distance in metres from a point to a polygon's edges, computed in
/// a local east/north metre frame centred on the point.
fn distance_to_polygon_m(lat: f64, lon: f64, verts: &[(f64, f64)]) -> f64 {
    let n = verts.len();
    if n == 0 {
        return f64::INFINITY;
    }
    let mpd = meters_per_deg_lat();
    let coslat = lat.to_radians().cos();
    let proj = |(vlat, vlon): (f64, f64)| -> (f64, f64) {
        ((vlon - lon) * mpd * coslat, (vlat - lat) * mpd)
    };
    let origin = (0.0, 0.0);
    if n == 1 {
        let p = proj(verts[0]);
        return (p.0 * p.0 + p.1 * p.1).sqrt();
    }
    let mut best = f64::INFINITY;
    let mut j = n - 1;
    for i in 0..n {
        let a = proj(verts[i]);
        let b = proj(verts[j]);
        best = best.min(point_segment_dist(origin, a, b));
        j = i;
    }
    best
}

/// Distance from point `p` to the segment `a`-`b`, all in metres.
fn point_segment_dist(p: (f64, f64), a: (f64, f64), b: (f64, f64)) -> f64 {
    let (px, py) = p;
    let (ax, ay) = a;
    let (bx, by) = b;
    let dx = bx - ax;
    let dy = by - ay;
    let len2 = dx * dx + dy * dy;
    let (cx, cy) = if len2 <= f64::EPSILON {
        (ax, ay)
    } else {
        let t = (((px - ax) * dx + (py - ay) * dy) / len2).clamp(0.0, 1.0);
        (ax + t * dx, ay + t * dy)
    };
    let ex = px - cx;
    let ey = py - cy;
    (ex * ex + ey * ey).sqrt()
}

/// Where a track stands relative to a protected zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneStatus {
    /// The track's latest fix is inside the zone: a breach.
    Inside,
    /// The track is outside but within the approach band and closing on the
    /// zone fast enough to matter.
    Approaching,
    /// The track is outside the zone and not closing on it.
    Clear,
}

impl ZoneStatus {
    /// Lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            ZoneStatus::Inside => "inside",
            ZoneStatus::Approaching => "approaching",
            ZoneStatus::Clear => "clear",
        }
    }
}

/// Thresholds for [`zone_breach`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct ZoneConfig {
    /// How far outside the boundary, in metres, a closing track still raises an
    /// `Approaching` alert. Default 500.
    pub approach_m: f64,
    /// Minimum closing speed, m/s, before an outside track counts as
    /// approaching rather than merely nearby. Default 0.5.
    pub min_closing_mps: f64,
}

impl Default for ZoneConfig {
    fn default() -> Self {
        ZoneConfig {
            approach_m: 500.0,
            min_closing_mps: 0.5,
        }
    }
}

impl ZoneConfig {
    /// A config with an explicit approach band and minimum closing speed.
    pub fn new(approach_m: f64, min_closing_mps: f64) -> ZoneConfig {
        ZoneConfig {
            approach_m,
            min_closing_mps,
        }
    }
}

/// A protected-zone judgement for one track.
#[derive(Debug, Clone)]
pub struct ZoneAlert {
    /// The on-air source of the track.
    pub transmitter: Transmitter,
    /// The track's primary UAS ID, if any.
    pub uas_id: Option<String>,
    /// Inside, approaching, or clear.
    pub status: ZoneStatus,
    /// Distance in metres from the track's latest fix to the zone boundary,
    /// `0.0` when inside.
    pub distance_m: f64,
    /// Closing speed on the boundary in m/s, from the last two fixes. Positive
    /// means getting closer; negative means moving away.
    pub closing_speed_mps: f64,
    /// Estimated seconds to reach the boundary, when approaching and closing.
    pub eta_s: Option<f64>,
}

impl ZoneAlert {
    /// `true` when the track is inside the zone or approaching it: the two
    /// states that warrant an operator alert.
    pub fn is_breach(&self) -> bool {
        matches!(self.status, ZoneStatus::Inside | ZoneStatus::Approaching)
    }
}

/// Evaluate one track against a protected zone.
///
/// Returns `None` only when the track has no decoded position. The returned
/// [`ZoneAlert`] always carries a [`ZoneStatus`]; use [`ZoneAlert::is_breach`]
/// or [`zone_alerts`] to keep just the ones that warrant an alert.
///
/// The closing speed is derived from the track's own position history (the
/// change in distance-to-boundary between the last two fixes), not from the
/// reported speed field, so a spoofed speed cannot hide an approach.
pub fn zone_breach(path: &TrackPath, zone: &ProtectedZone, cfg: &ZoneConfig) -> Option<ZoneAlert> {
    let last = path.fixes.last()?;
    let dist = zone.distance_to_boundary_m(last.lat, last.lon);
    let inside = zone.contains(last.lat, last.lon);

    let closing = if path.fixes.len() >= 2 {
        let prev = &path.fixes[path.fixes.len() - 2];
        let dt_s = last.t_ms.saturating_sub(prev.t_ms) as f64 / 1000.0;
        if dt_s > 0.0 {
            let d_prev = zone.distance_to_boundary_m(prev.lat, prev.lon);
            (d_prev - dist) / dt_s
        } else {
            0.0
        }
    } else {
        0.0
    };

    let status = if inside {
        ZoneStatus::Inside
    } else if dist <= cfg.approach_m && closing >= cfg.min_closing_mps {
        ZoneStatus::Approaching
    } else {
        ZoneStatus::Clear
    };

    let eta_s = if status == ZoneStatus::Approaching && closing > 0.0 {
        Some(dist / closing)
    } else {
        None
    };

    Some(ZoneAlert {
        transmitter: path.transmitter,
        uas_id: path.uas_id.clone(),
        status,
        distance_m: dist,
        closing_speed_mps: closing,
        eta_s,
    })
}

/// Evaluate many tracks and keep only the ones inside or approaching the zone,
/// worst first (inside before approaching, then nearest boundary).
pub fn zone_alerts(paths: &[TrackPath], zone: &ProtectedZone, cfg: &ZoneConfig) -> Vec<ZoneAlert> {
    let mut alerts: Vec<ZoneAlert> = paths
        .iter()
        .filter_map(|p| zone_breach(p, zone, cfg))
        .filter(ZoneAlert::is_breach)
        .collect();
    alerts.sort_by(|a, b| {
        let rank = |s: ZoneStatus| match s {
            ZoneStatus::Inside => 0,
            ZoneStatus::Approaching => 1,
            ZoneStatus::Clear => 2,
        };
        rank(a.status).cmp(&rank(b.status)).then(
            a.distance_m
                .partial_cmp(&b.distance_m)
                .unwrap_or(core::cmp::Ordering::Equal),
        )
    });
    alerts
}

/// Thresholds for [`loiter_check`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct LoiterConfig {
    /// A track counts as loitering when every fix in a window stays within
    /// this many metres of the window's centre. Covers both a hover (tight
    /// cluster) and a circular orbit (points around one centre). Default 150.
    pub radius_m: f64,
    /// How long, in milliseconds, the track must stay inside `radius_m` before
    /// it is flagged. Default 120000 (two minutes).
    pub min_duration_ms: u64,
    /// Minimum number of fixes in the window, so a pair of stale points cannot
    /// trip the check. Default 5.
    pub min_fixes: usize,
}

impl Default for LoiterConfig {
    fn default() -> Self {
        LoiterConfig {
            radius_m: 150.0,
            min_duration_ms: 120_000,
            min_fixes: 5,
        }
    }
}

impl LoiterConfig {
    /// A config with an explicit loiter radius, minimum hold time and minimum
    /// fix count.
    pub fn new(radius_m: f64, min_duration_ms: u64, min_fixes: usize) -> LoiterConfig {
        LoiterConfig {
            radius_m,
            min_duration_ms,
            min_fixes,
        }
    }
}

/// A loitering / surveillance judgement for one track.
#[derive(Debug, Clone)]
pub struct LoiterAlert {
    /// The on-air source of the track.
    pub transmitter: Transmitter,
    /// The track's primary UAS ID, if any.
    pub uas_id: Option<String>,
    /// The centre `(lat, lon)` the track has been holding over.
    pub center: (f64, f64),
    /// The largest distance, in metres, any fix in the window strayed from the
    /// centre: the size of the orbit or hover.
    pub radius_m: f64,
    /// How long the track held inside the centre, in milliseconds.
    pub duration_ms: u64,
    /// How many fixes make up the loiter window.
    pub fix_count: usize,
}

/// Flag a track that has been circling or hovering within a small radius of one
/// point for longer than [`LoiterConfig::min_duration_ms`].
///
/// Finds the longest contiguous run of fixes that all stay within
/// [`LoiterConfig::radius_m`] of that run's centre. A straight transit never
/// qualifies (its fixes spread far from any single centre); a hover (tight
/// cluster) and a circular orbit (fixes evenly around one centre) both do.
pub fn loiter_check(path: &TrackPath, cfg: &LoiterConfig) -> Option<LoiterAlert> {
    let f = &path.fixes;
    let n = f.len();
    if n < cfg.min_fixes || cfg.min_fixes == 0 {
        return None;
    }

    let mut best: Option<(usize, usize, f64, (f64, f64))> = None;
    for i in 0..n {
        for j in (i + cfg.min_fixes - 1)..n {
            let window = &f[i..=j];
            let center = centroid(window);
            let span = window
                .iter()
                .map(|x| distance_m(x.lat, x.lon, center.0, center.1))
                .fold(0.0_f64, f64::max);
            if span > cfg.radius_m {
                continue;
            }
            let dur = f[j].t_ms.saturating_sub(f[i].t_ms);
            if dur < cfg.min_duration_ms {
                continue;
            }
            let take = match best {
                None => true,
                Some((bi, bj, _, _)) => {
                    let best_dur = f[bj].t_ms.saturating_sub(f[bi].t_ms);
                    dur > best_dur || (dur == best_dur && (j - i) > (bj - bi))
                }
            };
            if take {
                best = Some((i, j, span, center));
            }
        }
    }

    best.map(|(i, j, span, center)| LoiterAlert {
        transmitter: path.transmitter,
        uas_id: path.uas_id.clone(),
        center,
        radius_m: span,
        duration_ms: f[j].t_ms.saturating_sub(f[i].t_ms),
        fix_count: j - i + 1,
    })
}

/// Evaluate many tracks and keep every loiter alert, longest hold first.
pub fn loiter_alerts(paths: &[TrackPath], cfg: &LoiterConfig) -> Vec<LoiterAlert> {
    let mut alerts: Vec<LoiterAlert> = paths.iter().filter_map(|p| loiter_check(p, cfg)).collect();
    alerts.sort_by_key(|a| core::cmp::Reverse(a.duration_ms));
    alerts
}

/// Arithmetic mean of a set of fixes' latitude and longitude. For the
/// site-scale windows here the planar mean is within centimetres of the true
/// spherical centroid.
fn centroid(fixes: &[Fix]) -> (f64, f64) {
    let n = fixes.len() as f64;
    let (slat, slon) = fixes
        .iter()
        .fold((0.0, 0.0), |(a, b), f| (a + f.lat, b + f.lon));
    (slat / n, slon / n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_contains_and_boundary_distance() {
        // One degree of latitude is about 111.2 km. A 1000 m circle at the
        // equator: a point 0.005 deg north (~556 m) is inside; 0.02 deg
        // (~2224 m) is outside by ~1224 m.
        let z = ProtectedZone::circle(0.0, 0.0, 1000.0);
        assert!(z.contains(0.005, 0.0));
        assert_eq!(z.distance_to_boundary_m(0.005, 0.0), 0.0);
        assert!(!z.contains(0.02, 0.0));
        let d = z.distance_to_boundary_m(0.02, 0.0);
        assert!((d - 1224.0).abs() < 20.0, "boundary distance {d}");
    }

    #[test]
    fn polygon_contains_and_edge_distance() {
        // A ~0.01 deg square (about 1.1 km on a side) near the equator.
        let square =
            ProtectedZone::polygon(vec![(0.0, 0.0), (0.0, 0.01), (0.01, 0.01), (0.01, 0.0)]);
        assert!(square.contains(0.005, 0.005));
        assert!(!square.contains(0.02, 0.005));
        assert_eq!(square.distance_to_boundary_m(0.005, 0.005), 0.0);
        // 0.005 deg north of the top edge is about 556 m outside.
        let d = square.distance_to_boundary_m(0.015, 0.005);
        assert!((d - 556.0).abs() < 15.0, "edge distance {d}");
    }

    #[test]
    fn point_segment_dist_is_perpendicular() {
        // Point (0, 10) to the x-axis segment (-5,0)-(5,0): distance 10.
        let d = point_segment_dist((0.0, 10.0), (-5.0, 0.0), (5.0, 0.0));
        assert!((d - 10.0).abs() < 1e-9, "{d}");
        // Past the end: nearest is the endpoint (5,0), distance sqrt(25+100).
        let d2 = point_segment_dist((10.0, 10.0), (-5.0, 0.0), (5.0, 0.0));
        assert!((d2 - (125.0_f64).sqrt()).abs() < 1e-9, "{d2}");
    }
}

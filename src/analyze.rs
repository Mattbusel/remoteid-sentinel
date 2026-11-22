//! The field analyzer: turn a set of already-decoded Remote ID tracks into a
//! flood verdict, a per-track fake score, and the one track most likely to be
//! the real drone.
//!
//! Everything here is receive-only. The sentinel reads broadcasts a sensor has
//! already received and decoded; it opens no radio and emits nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use remoteid::trust::AuthState;
use remoteid::{
    Assessment, Frame, Message, Observation, Reason, SerialNumber, Transmitter, Verdict,
};
use remoteid::{Tracker, TrackerConfig};

use crate::config::FieldConfig;
use crate::signature::{Signature, SignatureSet};

/// How badly the field is flooded with fakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodLevel {
    /// No sign of a coordinated flood or spoof.
    Clear,
    /// Some flood tells present; watch, do not yet treat every track as fake.
    Elevated,
    /// Strong evidence the airspace is flooded with fakes.
    Flooded,
}

impl FloodLevel {
    /// Lower-case name.
    pub fn name(self) -> &'static str {
        match self {
            FloodLevel::Clear => "clear",
            FloodLevel::Elevated => "elevated",
            FloodLevel::Flooded => "flooded",
        }
    }
}

/// The overall flood verdict with the confidence behind it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FloodVerdict {
    /// The graded level.
    pub level: FloodLevel,
    /// 0 (nothing) to 1 (certain flood).
    pub confidence: f32,
}

impl FloodVerdict {
    /// `true` when the level is [`FloodLevel::Flooded`].
    pub fn is_flood(self) -> bool {
        self.level == FloodLevel::Flooded
    }
}

/// One track's score: its carried per-unit library assessment, the sentinel's
/// cross-track fake signals, and how much it looks like the one real drone.
#[derive(Debug, Clone)]
pub struct TrackScore {
    /// The on-air source this track is keyed by.
    pub transmitter: Transmitter,
    /// The primary UAS ID shown for the track, if any.
    pub uas_id: Option<String>,
    /// The per-unit [`remoteid`] assessment, reused unchanged.
    pub per_unit: Assessment,
    /// The cross-track flood / spoof signatures the sentinel raised.
    pub fake_signals: SignatureSet,
    /// 0 (certainly fake) to 1 (looks like the genuine drone).
    pub real_score: f32,
    /// When this track is the chosen genuine one, the ordered reasons it was
    /// chosen. Empty otherwise.
    pub genuine_reasons: Vec<String>,
}

/// The assessment of a whole field of Remote ID tracks.
#[derive(Debug, Clone)]
pub struct FieldAssessment {
    /// Is the airspace flooded with fakes?
    pub flood: FloodVerdict,
    /// Every track, with its fake signals and real-drone score.
    pub tracks: Vec<TrackScore>,
    /// The track most likely to be the one genuine drone, if any survived.
    pub most_likely_real: Option<TrackScore>,
}

/// Everything the scorer needs about one track, gathered either from a
/// [`Tracker`] or from an observation stream.
struct TrackRaw {
    transmitter: Transmitter,
    uas_id: Option<String>,
    assessment: Assessment,
    first_seen_ms: u64,
    fix: Option<(f64, f64)>,
    rssi_dbm: Option<i8>,
    operator_pos: Option<(f64, f64)>,
    serials: Vec<String>,
    distinct_ids: usize,
    counter_values: Vec<u8>,
    frames: u64,
}

const KINEMATIC_REASONS: [Reason; 5] = [
    Reason::Teleport,
    Reason::SpeedImplausible,
    Reason::ReportedSpeedMismatch,
    Reason::ReportedCourseMismatch,
    Reason::VerticalRateImplausible,
];

impl FieldAssessment {
    /// Analyze a populated [`Tracker`] with the default [`FieldConfig`].
    ///
    /// Works entirely from the tracker's final state. The cross-track checks
    /// that need the full message history, the per-source UAS-ID fan-out and
    /// the shared-counter sequence, are only partially visible from a tracker
    /// (it keeps the latest Basic IDs per transmitter, not every ID a flood
    /// source cycled through), so [`FieldAssessment::from_observations`] is the
    /// fuller path when the raw stream is in hand.
    pub fn from_tracker(tracker: &Tracker, now_ms: u64) -> FieldAssessment {
        Self::from_tracker_with(tracker, now_ms, &FieldConfig::default())
    }

    /// [`FieldAssessment::from_tracker`] with an explicit config.
    pub fn from_tracker_with(tracker: &Tracker, now_ms: u64, cfg: &FieldConfig) -> FieldAssessment {
        let mut raws = Vec::new();
        for (tx, u) in tracker.iter() {
            let assessment = tracker.assessment(tx, now_ms).unwrap_or(u.assessment);
            let mut serials = Vec::new();
            let mut ids = BTreeSet::new();
            for b in u.data.basic_id.iter().flatten() {
                if let Some(id) = b.uas_id_str().filter(|s| !s.is_empty()) {
                    ids.insert(id.to_string());
                    if b.serial_number().is_some() {
                        serials.push(id.to_string());
                    }
                }
            }
            raws.push(TrackRaw {
                transmitter: *tx,
                uas_id: u.uas_id(),
                assessment,
                first_seen_ms: u.first_seen,
                fix: u.last_fix().map(|(_, lat, lon, _)| (lat, lon)),
                rssi_dbm: u.rssi_dbm,
                operator_pos: u.data.system.as_ref().and_then(|s| s.operator_position()),
                serials,
                distinct_ids: ids.len(),
                counter_values: Vec::new(),
                frames: u.stats.received,
            });
        }
        score_field(raws, cfg)
    }

    /// Analyze a stream of already-decoded observations with the default
    /// [`FieldConfig`].
    ///
    /// Each `(transmitter, observation)` is fed through a [`remoteid`]
    /// [`Tracker`] so per-unit grading is exactly the library's, while the
    /// sentinel accumulates the cross-track history (per-source fan-out,
    /// counter sequences, serials, operator positions) the tracker discards.
    /// This is the receive-only equivalent of a sensor replaying what it heard.
    pub fn from_observations<'a, I>(obs: I, now_ms: u64) -> FieldAssessment
    where
        I: IntoIterator<Item = (Transmitter, Observation<'a>)>,
    {
        Self::from_observations_with(obs, now_ms, &FieldConfig::default())
    }

    /// [`FieldAssessment::from_observations`] with an explicit config.
    pub fn from_observations_with<'a, I>(obs: I, now_ms: u64, cfg: &FieldConfig) -> FieldAssessment
    where
        I: IntoIterator<Item = (Transmitter, Observation<'a>)>,
    {
        #[derive(Default)]
        struct Accum {
            first_seen_ms: u64,
            ids: BTreeSet<String>,
            serials: BTreeSet<String>,
            counters: BTreeSet<u8>,
            operator_pos: Option<(f64, f64)>,
            frames: u64,
        }

        let mut tracker = Tracker::new(TrackerConfig {
            trust: cfg.trust,
            ..TrackerConfig::default()
        });
        let mut accums: HashMap<Transmitter, Accum> = HashMap::new();

        for (tx, o) in obs {
            tracker.observe(tx, &o);
            let a = accums.entry(tx).or_insert_with(|| Accum {
                first_seen_ms: o.now_ms,
                ..Accum::default()
            });
            a.first_seen_ms = a.first_seen_ms.min(o.now_ms);
            a.frames += 1;
            if let Some(c) = o.counter {
                a.counters.insert(c);
            }
            if let Ok(frame) = Frame::decode(o.payload) {
                frame.for_each_message(|m| match m {
                    Message::BasicId(b) => {
                        if let Some(id) = b.uas_id_str().filter(|s| !s.is_empty()) {
                            a.ids.insert(id.to_string());
                            if b.serial_number().is_some() {
                                a.serials.insert(id.to_string());
                            }
                        }
                    }
                    Message::System(s) => {
                        if let Some(p) = s.operator_position() {
                            a.operator_pos = Some(p);
                        }
                    }
                    _ => {}
                });
            }
        }

        let mut raws = Vec::new();
        for (tx, a) in accums {
            let entry = tracker.get(&tx);
            let assessment = tracker
                .assessment(&tx, now_ms)
                .or_else(|| entry.map(|e| e.assessment))
                .unwrap_or_default();
            raws.push(TrackRaw {
                transmitter: tx,
                uas_id: entry.and_then(|e| e.uas_id()),
                assessment,
                first_seen_ms: a.first_seen_ms,
                fix: entry
                    .and_then(|e| e.last_fix())
                    .map(|(_, lat, lon, _)| (lat, lon)),
                rssi_dbm: entry.and_then(|e| e.rssi_dbm),
                operator_pos: a.operator_pos,
                serials: a.serials.into_iter().collect(),
                distinct_ids: a.ids.len(),
                counter_values: a.counters.into_iter().collect(),
                frames: a.frames,
            });
        }
        score_field(raws, cfg)
    }
}

/// Strips trailing decimal digits: the varying suffix of a sequential serial.
fn serial_prefix(serial: &str) -> &str {
    serial.trim_end_matches(|c: char| c.is_ascii_digit())
}

/// The template key of a serial: manufacturer code plus the non-numeric body
/// prefix, so `1581.FAKE00007` and `1581.FAKE00042` share a key.
fn template_key(serial: &str) -> Option<String> {
    let sn = SerialNumber::parse(serial)?;
    Some(format!(
        "{}|{}",
        sn.manufacturer_code,
        serial_prefix(sn.serial)
    ))
}

fn op_key(pos: (f64, f64)) -> (i64, i64) {
    ((pos.0 * 1e5).round() as i64, (pos.1 * 1e5).round() as i64)
}

/// Builds the field assessment from gathered per-track data.
fn score_field(raws: Vec<TrackRaw>, cfg: &FieldConfig) -> FieldAssessment {
    let n = raws.len();
    let mut sigs: Vec<SignatureSet> = vec![SignatureSet::new(); n];

    // A reason shared by nearly every track in the field is an artifact of the
    // sensor or its environment (a clock the whole site reads the same way, a
    // signal floor), not a per-track spoof tell. A suspicious verdict that
    // rests only on such field-common reasons is not evidence of a flood.
    let field_common = |reason: Reason| -> bool {
        if n < 2 {
            return false;
        }
        let hits = raws
            .iter()
            .filter(|r| r.assessment.reasons.contains(reason))
            .count();
        hits * 5 >= n * 4
    };

    // --- per-unit signals carried up from the library ---
    for (i, r) in raws.iter().enumerate() {
        let distinctive = r
            .assessment
            .reasons
            .iter()
            .any(|reason| !field_common(reason));
        let graded_fake = r.assessment.verdict == Verdict::Spoofed
            || (r.assessment.verdict == Verdict::Suspicious && distinctive);
        if graded_fake {
            sigs[i].insert(Signature::PerUnitSpoofedOrSuspicious);
        }
        if r.assessment.spoofer.is_some() || r.assessment.reasons.contains(Reason::KnownSpoofer) {
            sigs[i].insert(Signature::KnownSpooferFingerprint);
        }
        if KINEMATIC_REASONS
            .iter()
            .any(|&k| r.assessment.reasons.contains(k))
        {
            sigs[i].insert(Signature::ImpossibleKinematics);
        }
    }

    // --- fan-out: one source, many distinct IDs ---
    for (i, r) in raws.iter().enumerate() {
        if r.distinct_ids >= cfg.min_fanout {
            sigs[i].insert(Signature::OneSourceManyIds);
        }
    }

    // --- templated / sequential serials across tracks ---
    let mut by_template: BTreeMap<String, (BTreeSet<String>, Vec<usize>)> = BTreeMap::new();
    for (i, r) in raws.iter().enumerate() {
        for s in &r.serials {
            if let Some(key) = template_key(s) {
                let e = by_template.entry(key).or_default();
                e.0.insert(s.clone());
                e.1.push(i);
            }
        }
    }
    for (distinct, members) in by_template.values() {
        if distinct.len() >= cfg.serial_template_min_group {
            for &i in members {
                sigs[i].insert(Signature::TemplatedSerial);
            }
        }
    }

    // --- frozen / lockstep counters shared across tracks ---
    // A real transmitter counts up; a track that emitted several frames under
    // one single counter value is frozen. Two or more frozen tracks sharing
    // one value are a templated flood.
    let mut by_frozen: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
    for (i, r) in raws.iter().enumerate() {
        if r.frames >= 8 && r.counter_values.len() == 1 {
            by_frozen.entry(r.counter_values[0]).or_default().push(i);
        }
    }
    for members in by_frozen.values() {
        if members.len() >= 2 {
            for &i in members {
                sigs[i].insert(Signature::FrozenOrIdenticalCounter);
            }
        }
    }

    // --- shared operator (pilot) position across tracks ---
    let mut by_op: BTreeMap<(i64, i64), Vec<usize>> = BTreeMap::new();
    for (i, r) in raws.iter().enumerate() {
        if let Some(p) = r.operator_pos {
            by_op.entry(op_key(p)).or_default().push(i);
        }
    }
    for members in by_op.values() {
        if members.len() >= cfg.operator_colocation_min {
            for &i in members {
                sigs[i].insert(Signature::SharedOperatorPosition);
            }
        }
    }

    // --- tight RSSI + position cluster ---
    for i in 0..n {
        let (Some(ri), Some(pi)) = (raws[i].rssi_dbm, raws[i].fix) else {
            continue;
        };
        let group = raws
            .iter()
            .filter(|other| {
                let (Some(rj), Some(pj)) = (other.rssi_dbm, other.fix) else {
                    return false;
                };
                let close_rssi =
                    (ri as i16 - rj as i16).unsigned_abs() <= cfg.rssi_cluster_db as u16;
                let close_pos =
                    remoteid::geo::distance_m(pi.0, pi.1, pj.0, pj.1) <= cfg.geo_cluster_m;
                close_rssi && close_pos
            })
            .count();
        if group >= cfg.rssi_cluster_min {
            sigs[i].insert(Signature::TightRssiPositionCluster);
        }
    }

    // --- count spike: many transmitters first heard in one window ---
    for i in 0..n {
        let t0 = raws[i].first_seen_ms;
        let c = raws
            .iter()
            .filter(|r| r.first_seen_ms.abs_diff(t0) <= cfg.count_spike_window_ms)
            .count();
        if c >= cfg.count_spike_min {
            sigs[i].insert(Signature::CountSpike);
        }
    }

    // --- assemble per-track scores ---
    let mut tracks: Vec<TrackScore> = Vec::with_capacity(n);
    for (i, r) in raws.iter().enumerate() {
        let (real_score, reasons) = real_score(r, &sigs[i], cfg);
        tracks.push(TrackScore {
            transmitter: r.transmitter,
            uas_id: r.uas_id.clone(),
            per_unit: r.assessment,
            fake_signals: sigs[i],
            real_score,
            genuine_reasons: reasons,
        });
    }

    // --- genuine-track selection ---
    let mut best: Option<usize> = None;
    for (i, r) in raws.iter().enumerate() {
        let fake = &sigs[i];
        let authed = matches!(r.assessment.auth, AuthState::Verified | AuthState::Trusted);
        let eligible = !fake.disqualifies_genuine()
            && r.assessment.verdict != Verdict::Spoofed
            && (!cfg.requires_auth || authed);
        if !eligible {
            continue;
        }
        best = Some(match best {
            None => i,
            Some(b) => {
                let (bs, bf) = (tracks[b].real_score, raws[b].frames);
                let (cs, cf) = (tracks[i].real_score, r.frames);
                if cs > bs || (cs == bs && cf > bf) {
                    i
                } else {
                    b
                }
            }
        });
    }
    let most_likely_real = best.map(|i| tracks[i].clone());

    let flood = flood_verdict(&tracks, cfg);

    FieldAssessment {
        flood,
        tracks,
        most_likely_real,
    }
}

/// Positive score for one track being the genuine drone, with the reasons.
fn real_score(r: &TrackRaw, fake: &SignatureSet, cfg: &FieldConfig) -> (f32, Vec<String>) {
    let mut score = 0.5f32;
    let mut reasons: Vec<String> = Vec::new();

    score -= 0.3 * fake.total_weight();

    let kinematic = fake.contains(Signature::ImpossibleKinematics);
    let trackable = r.fix.is_some() && r.frames >= 4;
    if !kinematic && trackable {
        score += 0.2;
        reasons.push("consistent moving track with sane kinematics".to_string());
    }

    let authed = matches!(r.assessment.auth, AuthState::Verified | AuthState::Trusted);
    if authed {
        score += 0.3;
        reasons.push("DRIP authentication verified".to_string());
    }

    match r.assessment.verdict {
        Verdict::Authenticated => {
            score += 0.2;
            reasons.push("library graded the unit authenticated".to_string());
        }
        Verdict::Plausible => {
            score += 0.1;
            reasons
                .push("library verdict plausible: nothing contradicts the broadcast".to_string());
        }
        _ => {}
    }

    if r.distinct_ids <= 1 {
        score += 0.1;
        reasons.push("single stable identity, no per-source fan-out".to_string());
    }

    if !fake.contains(Signature::TemplatedSerial) && !r.serials.is_empty() {
        score += 0.1;
        reasons.push("serial sits outside the templated fake block".to_string());
    }

    if cfg.requires_auth && !authed {
        reasons.clear();
        reasons.push(
            "rejected: config requires authentication and this track is unauthenticated"
                .to_string(),
        );
    }

    (score.clamp(0.0, 1.0), reasons)
}

/// The overall flood verdict from the per-track signatures.
fn flood_verdict(tracks: &[TrackScore], cfg: &FieldConfig) -> FloodVerdict {
    if tracks.is_empty() {
        return FloodVerdict {
            level: FloodLevel::Clear,
            confidence: 0.0,
        };
    }
    let n = tracks.len() as f32;
    let frac =
        |s: Signature| tracks.iter().filter(|t| t.fake_signals.contains(s)).count() as f32 / n;

    // Fan-out is the signature flood tell: scale by how far past the threshold
    // the worst source is.
    let max_fanout = tracks
        .iter()
        .filter(|t| t.fake_signals.contains(Signature::OneSourceManyIds))
        .count();
    let fan_out_term = if max_fanout > 0 { 1.0 } else { 0.0 };

    // Only a hard spoofed verdict drives the flood score; a merely suspicious
    // unit (soft, often shared across the field) is weighed through its own
    // signature below.
    let spoofed_frac = tracks
        .iter()
        .filter(|t| t.per_unit.verdict == Verdict::Spoofed)
        .count() as f32
        / n;

    let confidence = (0.9 * fan_out_term
        + 0.7 * frac(Signature::KnownSpooferFingerprint)
        + 0.6 * spoofed_frac
        + 0.5 * frac(Signature::TemplatedSerial)
        + 0.5 * frac(Signature::FrozenOrIdenticalCounter)
        + 0.4 * frac(Signature::TightRssiPositionCluster)
        + 0.4 * frac(Signature::SharedOperatorPosition)
        + 0.3 * frac(Signature::CountSpike))
    .clamp(0.0, 1.0);

    let level = if confidence >= 0.6 {
        FloodLevel::Flooded
    } else if confidence >= 0.25 {
        FloodLevel::Elevated
    } else {
        FloodLevel::Clear
    };
    let _ = cfg;
    FloodVerdict { level, confidence }
}

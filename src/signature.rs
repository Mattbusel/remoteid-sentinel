//! The cross-track signatures the sentinel raises over a field of tracks.
//!
//! Each [`Signature`] is a tell that a track is part of a flood or a spoof,
//! computed by comparing tracks against each other (or by carrying a per-unit
//! [`remoteid`] verdict up to the field level). Every signature has a
//! documented [`weight`](Signature::weight): how much it pushes a track away
//! from being treated as the one genuine drone, and how much it adds to the
//! overall flood score.

use core::fmt;

/// One flagged tell about a track.
///
/// The variants map onto the detector design: some wrap a per-unit
/// [`remoteid::trust::Reason`] carried up from the library, others are
/// aggregates the sentinel computes across the whole field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Signature {
    /// One on-air source address broadcast many distinct primary UAS IDs in
    /// the window (fan-out). Reuses the library's per-source tracking and adds
    /// the fan-out count. Strong flood tell.
    OneSourceManyIds = 0,
    /// Dozens of tracks at near-identical signal strength and/or an
    /// implausibly tight position cluster: one physical emitter wearing many
    /// identities.
    TightRssiPositionCluster = 1,
    /// The track's serial is part of a templated or sequential block shared
    /// across many tracks (common prefix, incrementing or fixed suffix).
    TemplatedSerial = 2,
    /// Many "different" drones share one frozen or lockstep message-counter
    /// sequence.
    FrozenOrIdenticalCounter = 3,
    /// Per-unit kinematic impossibility carried up from the library: teleport,
    /// impossible speed, or reported speed / course / vertical-rate mismatch.
    ImpossibleKinematics = 4,
    /// The track shares one identical operator (pilot) position with many
    /// other "different" drones.
    SharedOperatorPosition = 5,
    /// The library already graded this unit spoofed or suspicious.
    PerUnitSpoofedOrSuspicious = 6,
    /// The track carries the fingerprint of a known public spoofing tool.
    KnownSpooferFingerprint = 7,
    /// The track's transmitter appeared inside a sudden spawn of many new
    /// transmitters (count spike / flood onset).
    CountSpike = 8,
}

impl Signature {
    /// Every signature, in code order.
    pub const ALL: [Signature; 9] = [
        Signature::OneSourceManyIds,
        Signature::TightRssiPositionCluster,
        Signature::TemplatedSerial,
        Signature::FrozenOrIdenticalCounter,
        Signature::ImpossibleKinematics,
        Signature::SharedOperatorPosition,
        Signature::PerUnitSpoofedOrSuspicious,
        Signature::KnownSpooferFingerprint,
        Signature::CountSpike,
    ];

    /// Stable snake-case name.
    pub fn name(self) -> &'static str {
        match self {
            Signature::OneSourceManyIds => "one_source_many_ids",
            Signature::TightRssiPositionCluster => "tight_rssi_position_cluster",
            Signature::TemplatedSerial => "templated_serial",
            Signature::FrozenOrIdenticalCounter => "frozen_or_identical_counter",
            Signature::ImpossibleKinematics => "impossible_kinematics",
            Signature::SharedOperatorPosition => "shared_operator_position",
            Signature::PerUnitSpoofedOrSuspicious => "per_unit_spoofed_or_suspicious",
            Signature::KnownSpooferFingerprint => "known_spoofer_fingerprint",
            Signature::CountSpike => "count_spike",
        }
    }

    /// How much this signature weighs against a track, in the range used by
    /// both the flood score and the genuine-track scorer.
    ///
    /// The weights are graded the way the library grades its reasons:
    /// identity and fingerprint tells are strongest, structural flood tells
    /// (fan-out, shared counter, templated serials, tight cluster, shared
    /// operator) are strong, and the softer onset tell (count spike) is
    /// moderate.
    pub fn weight(self) -> f32 {
        match self {
            // A matched spoofing tool, or two radios proven to clone one
            // identity, is as strong as evidence gets.
            Signature::KnownSpooferFingerprint => 1.0,
            Signature::PerUnitSpoofedOrSuspicious => 0.9,
            Signature::ImpossibleKinematics => 0.9,
            // Structural flood tells: each one alone is strong.
            Signature::OneSourceManyIds => 0.8,
            Signature::FrozenOrIdenticalCounter => 0.7,
            Signature::TemplatedSerial => 0.7,
            Signature::SharedOperatorPosition => 0.6,
            Signature::TightRssiPositionCluster => 0.6,
            // Onset: suggestive, matures into the others.
            Signature::CountSpike => 0.4,
        }
    }

    /// Whether this signature, on its own, disqualifies a track from being
    /// named the one genuine drone.
    ///
    /// A soft, graded [`Signature::PerUnitSpoofedOrSuspicious`] is deliberately
    /// not here: a merely *suspicious* unit is demoted in the ranking, not
    /// excluded (the genuine drone in a hostile field can itself look
    /// suspicious for a window). A *spoofed* verdict is excluded separately by
    /// the analyzer, which can read the graded verdict directly.
    pub fn disqualifies_genuine(self) -> bool {
        matches!(
            self,
            Signature::KnownSpooferFingerprint
                | Signature::ImpossibleKinematics
                | Signature::OneSourceManyIds
                | Signature::TemplatedSerial
                | Signature::FrozenOrIdenticalCounter
        )
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A small set of [`Signature`]s, modelled on the library's `ReasonSet`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SignatureSet(u16);

impl SignatureSet {
    /// An empty set.
    pub fn new() -> Self {
        SignatureSet(0)
    }

    /// Adds a signature.
    pub fn insert(&mut self, s: Signature) {
        self.0 |= 1 << s as u8;
    }

    /// `true` if `s` is present.
    pub fn contains(&self, s: Signature) -> bool {
        self.0 & (1 << s as u8) != 0
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Number of signatures present.
    pub fn len(&self) -> usize {
        self.0.count_ones() as usize
    }

    /// The signatures present, in code order.
    pub fn iter(&self) -> impl Iterator<Item = Signature> + '_ {
        Signature::ALL
            .iter()
            .copied()
            .filter(move |s| self.contains(*s))
    }

    /// Summed [`Signature::weight`] of every signature present.
    pub fn total_weight(&self) -> f32 {
        self.iter().map(Signature::weight).sum()
    }

    /// `true` if any present signature disqualifies the track from being the
    /// genuine one.
    pub fn disqualifies_genuine(&self) -> bool {
        self.iter().any(Signature::disqualifies_genuine)
    }
}

impl fmt::Debug for SignatureSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_round_trips() {
        let mut s = SignatureSet::new();
        assert!(s.is_empty());
        s.insert(Signature::OneSourceManyIds);
        s.insert(Signature::CountSpike);
        assert_eq!(s.len(), 2);
        assert!(s.contains(Signature::OneSourceManyIds));
        assert!(!s.contains(Signature::TemplatedSerial));
        let names: Vec<_> = s.iter().map(|x| x.name()).collect();
        assert_eq!(names, ["one_source_many_ids", "count_spike"]);
    }

    #[test]
    fn names_and_codes_are_unique() {
        for (i, s) in Signature::ALL.iter().enumerate() {
            assert_eq!(*s as usize, i);
            assert_eq!(
                Signature::ALL
                    .iter()
                    .filter(|o| o.name() == s.name())
                    .count(),
                1
            );
        }
    }
}

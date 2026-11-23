//! Receive-only flood and spoof analysis for counter-UAS sensors.
//!
//! `remoteid-sentinel` takes Remote ID broadcasts a counter-UAS sensor has
//! **already received and decoded** and answers two questions a detector
//! operator at an airport, stadium, prison or base actually asks:
//!
//! 1. *Is this airspace flooded with fakes?* ([`FloodVerdict`])
//! 2. *If one of these is a real drone, which one?* ([`FieldAssessment::most_likely_real`])
//!
//! It is the analysis layer on top of [`remoteid`] 0.3.3: every per-unit
//! judgement is the library's own [`Assessment`](remoteid::Assessment), and the
//! sentinel adds the cross-track [signatures](Signature) that only show up when
//! you look at the whole field at once, a per-source UAS-ID fan-out, a shared
//! frozen counter, a templated serial block, a tight RSSI or position cluster,
//! one pilot position under dozens of "different" drones, a sudden spawn of
//! transmitters, then ranks the survivors to point security at the track most
//! likely to be the one real aircraft.
//!
//! Think of it as the analyzer half of an antivirus: the detector decodes, the
//! sentinel grades, and [`remoteid-scenario`](https://crates.io/crates/remoteid-scenario)
//! is the test-sample suite you prove it against.
//!
//! # Hard boundaries
//!
//! This crate is **receive-only analysis**. State these when you integrate it.
//!
//! * **No radio.** It never opens an SDR, a Bluetooth or Wi-Fi adapter, or any
//!   device. It only reads broadcasts a sensor already decoded.
//! * **No transmit path.** It never broadcasts and emits no RF. It produces a
//!   verdict, not a frame.
//! * **No BLE / Wi-Fi / SDR / HackRF / ESP32 / nRF support**, and no firmware
//!   flashing.
//! * **No instructions for broadcasting into real airspace**, and **no evasion
//!   guidance.** Everything here helps a defender grade what was received.
//!
//! If a change would add a transmit or broadcast capability, it does not belong
//! in this crate.
//!
//! # Entry points
//!
//! * [`FieldAssessment::from_tracker`] analyzes a populated [`remoteid::Tracker`].
//! * [`FieldAssessment::from_observations`] replays a stream of already-decoded
//!   observations through a tracker and keeps the cross-track history the
//!   tracker discards. This is the fuller path and the one to prefer when the
//!   raw decoded stream is in hand.
//!
//! Both drive [`remoteid`]'s own tracker and trust state, so per-unit grading
//! matches the library exactly.
//!
//! Once the real track is in hand, the [`zone`] module answers what the site
//! operator asks next: [`zone_breach`] reports whether a tracked drone is
//! inside a protected area or approaching it (with distance, closing speed and
//! a time-to-boundary estimate), and [`loiter_check`] flags a drone that has
//! been circling or hovering over one point for longer than a threshold. Both
//! are receive-only geometry over the positions a sensor already decoded; feed
//! them the tracks the flood analysis did not flag.
//!
//! # Example
//!
//! ```no_run
//! use remoteid::{Observation, Transmitter, Transport};
//! use remoteid_sentinel::{FieldAssessment, FloodLevel};
//!
//! # fn decoded_stream() -> Vec<(Transmitter, Vec<u8>)> { Vec::new() }
//! // A sensor hands you what it already received and decoded.
//! let frames = decoded_stream();
//! let obs = frames.iter().map(|(tx, payload)| {
//!     (*tx, Observation::new(Transport::Bluetooth4, None, payload, 0))
//! });
//! let field = FieldAssessment::from_observations(obs, 10_000);
//! if field.flood.level == FloodLevel::Flooded {
//!     if let Some(real) = &field.most_likely_real {
//!         // Point security at `real.transmitter`.
//!         let _ = real;
//!     }
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyze;
pub mod config;
pub mod signature;
pub mod zone;

pub use analyze::{FieldAssessment, FloodLevel, FloodVerdict, TrackScore};
pub use config::FieldConfig;
pub use signature::{Signature, SignatureSet};
pub use zone::{
    loiter_alerts, loiter_check, zone_alerts, zone_breach, Fix, LoiterAlert, LoiterConfig,
    ProtectedZone, TrackPath, ZoneAlert, ZoneConfig, ZoneStatus,
};

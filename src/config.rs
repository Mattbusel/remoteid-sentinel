//! Tuning for the field analyzer.

use remoteid::TrustConfig;

/// Settings for [`crate::FieldAssessment`].
///
/// The [`trust`](FieldConfig::trust) config is passed straight through to the
/// library so per-unit grading is exactly what [`remoteid`] would produce; the
/// rest are the thresholds for the sentinel's own cross-track signatures.
///
/// Times are milliseconds of the sensor's monotonic clock, matching
/// [`remoteid`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct FieldConfig {
    /// Per-unit trust config, passed through to the library unchanged.
    pub trust: TrustConfig,
    /// Window for the count-spike / flood-onset check: transmitters first
    /// heard within this many milliseconds of each other count toward one
    /// spike. Default 1000.
    pub count_spike_window_ms: u64,
    /// How many transmitters must appear inside one `count_spike_window_ms`
    /// before the spike fires. Default 10.
    pub count_spike_min: usize,
    /// How many distinct primary UAS IDs one source address must emit in the
    /// window before [`crate::Signature::OneSourceManyIds`] fires. Default 5.
    pub min_fanout: usize,
    /// Signal-strength spread, in dB, within which tracks count as one RSSI
    /// cluster. Default 3.
    pub rssi_cluster_db: i8,
    /// How many tracks must share an RSSI (and tight position) cluster before
    /// [`crate::Signature::TightRssiPositionCluster`] fires. Default 6.
    pub rssi_cluster_min: usize,
    /// Radius, in metres, within which positions count as one tight cluster.
    /// Default 75.
    pub geo_cluster_m: f64,
    /// How many tracks must share a serial template before
    /// [`crate::Signature::TemplatedSerial`] fires. Default 5.
    pub serial_template_min_group: usize,
    /// How many tracks must share one operator position before
    /// [`crate::Signature::SharedOperatorPosition`] fires. Default 3.
    pub operator_colocation_min: usize,
    /// When true, a track can only be named the genuine drone if it carries a
    /// verified or trusted DRIP authentication state. Default `false`, because
    /// almost no aircraft flying today authenticate; turn it on where every
    /// legitimate operator in the protected volume is known to sign.
    pub requires_auth: bool,
}

impl Default for FieldConfig {
    fn default() -> Self {
        FieldConfig {
            trust: TrustConfig::default(),
            count_spike_window_ms: 1000,
            count_spike_min: 10,
            min_fanout: 5,
            rssi_cluster_db: 3,
            rssi_cluster_min: 6,
            geo_cluster_m: 75.0,
            serial_template_min_group: 5,
            operator_colocation_min: 3,
            requires_auth: false,
        }
    }
}

impl FieldConfig {
    /// A config with the given per-unit trust settings and the default
    /// thresholds.
    pub fn with_trust(trust: TrustConfig) -> Self {
        FieldConfig {
            trust,
            ..FieldConfig::default()
        }
    }
}

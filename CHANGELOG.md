# Changelog

All notable changes to `remoteid-sentinel` are recorded here. The format
follows Keep a Changelog, and the project uses semantic versioning.

## 0.2.0

Added the two threat questions a site operator acts on once the real drone is
found, as a new receive-only `zone` module over already-decoded track
positions. No radio, no transmit path, no breaking API change.

### Added

- **Protected-zone breach.** `ProtectedZone` (a circle around a point or a
  polygon perimeter) plus `zone_breach` / `zone_alerts` report, per track,
  whether a drone is inside the zone or approaching it, with the distance to the
  boundary, the closing speed, and an estimated time to the boundary. The
  concrete result an operator gets is "a drone breached the perimeter" or "a
  drone is 250 m out, closing at 12 m/s, 21 s to the fence," not "drones exist."
  The closing speed is derived from the track's own position history, so a
  spoofed speed field cannot hide an approach.
- **Loitering / surveillance.** `loiter_check` / `loiter_alerts` flag a track
  that has been circling or hovering within a small radius of one point for
  longer than a threshold, reporting the centre, the orbit radius and the hold
  time: "this drone has been orbiting the facility for three minutes." The check
  returns the longest run of fixes that stay inside the radius, so a transit is
  not mistaken for a loiter.
- `TrackPath::from_observations` decodes an already-received observation stream
  into one position history per track, the receive-only input both checks run
  on.
- Public geometry on `ProtectedZone`: `contains` and `distance_to_boundary_m`
  (haversine great-circle distance, even-odd ray-cast point-in-polygon, and
  point-to-edge distance in a local metre frame).
- `ZoneConfig` and `LoiterConfig` with documented defaults and `new`
  constructors.

### Notes

- Tests build the tracks as spec-compliant Remote ID streams encoded and
  decoded through the `remoteid` library: a `remoteid-scenario` flood whose
  genuine track flies a known straight line (for the breach and
  approach cases), and a circular orbit and a hover constructed from cited
  circle geometry (for the loiter cases). Distances and bearings are checked
  against hand-computed spec values.

## 0.1.0

- Initial release: receive-only Remote ID flood and spoof analyzer. Grades how
  badly a field of decoded tracks is flooded with fakes (`FloodVerdict`) and
  points security at the single track most likely to be the one real drone
  (`FieldAssessment::most_likely_real`), built on the published `remoteid`
  0.3.3 per-unit assessment with cross-track signatures the sentinel raises over
  the whole field.

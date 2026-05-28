# Event-Stream Observation Model

**Status:** Accepted

State changes are observed through a per-instance event stream of immutable, self-contained values — each event carries a complete snapshot of what changed, so an observer never queries back and so cannot race against a newer change. Events emit in a single total order fixed at the commit point, each tagged with a monotonically increasing identifier; multiple observers receive independent cursors over the same stream so observation is concurrent across observers without becoming a throughput bottleneck. An observer that exceeds its bounded buffer is told it has lagged and by how many events, and recovers by querying the library for current state — the snapshot is tagged with the identifier of the last event it reflects, so the observer resumes from exactly that point with no gap and no replay.

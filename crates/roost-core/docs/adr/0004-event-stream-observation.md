# App-owned observation

**Status:** Superseded for v0.16.0

The [system observation decision](../../../../docs/adr/0004-per-instance-event-stream.md) replaces
the per-instance Event Stream. Core returns typed change data and recovery signals with conditional
state updates. Hosts commit required effects durably and observe their stores through platform
facilities. There are no Rust observer buffers, cursors, or snapshot-resume objects.

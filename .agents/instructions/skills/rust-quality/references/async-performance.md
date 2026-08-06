# Async and Performance

- Make a function `async` only when its natural implementation waits for an event it does not produce, such as a network response, peer message, subscriber pull, or timer.
- Require at least one contract reason for suspension: interleaving waits, cancellation, timeout, retry, or backpressure. A `Stream` whose items arrive over time qualifies.
- Keep AEAD, KDF, signing, other CPU work, and single bounded syscalls synchronous. “Could block” alone does not justify `async`.
- Do not hide blocking or unbounded work in an async task. Move genuinely blocking work to the subsystem's explicit blocking boundary.
- Bound externally driven loops, allocations, queues, skipped-key storage, and decoded payload sizes before expensive work.
- Document caller-visible cost only when clients need it for scheduling, resource planning, or avoiding repeated expensive work.

# Async Rules

- A function is `async` only when its natural implementation suspends on an event it does not produce — network response, peer message, subscriber pull, timer
- Suspension justifies `async` when at least one of these holds:
  - the surrounding subsystem can interleave multiple such waits
  - cancellation, timeout, retries, or backpressure are part of the operation's contract
- Functions returning a `Stream` whose items arrive over time qualify
- CPU-bound work (AEAD, KDFs, signing), single bounded syscalls (one keychain read), and "could block in theory" are not justification

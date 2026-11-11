# Ordering Discovery Keys

A contact orders discovery keys by their signed creation time, then by epoch, because restoring an older backup can reuse an epoch number. The cost is that a rotation signed while the clock was behind stays ignored until a later rotation's time passes the stored one.

# Ordering Discovery Keys

A contact orders discovery keys by their signed creation time, then by epoch, because restoring an older backup can reuse an epoch number. The cost is that contacts ignore a rotation signed while the device's clock was behind, until a later rotation's time passes the stored one.

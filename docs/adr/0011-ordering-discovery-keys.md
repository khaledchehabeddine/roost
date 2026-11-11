# Ordering Discovery Keys

Restoring an older backup continues from that backup's epoch, so two discovery keys can share an epoch number. So a contact takes a discovery key as newer only if the identity key signed it with a later creation time, or the same time and a higher epoch. The cost is that a rotation signed while the clock was behind stays ignored until a later rotation's time passes the stored one.

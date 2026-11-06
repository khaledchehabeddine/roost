# Discovery Key Update Ordering

Restoring an older backup continues from that backup's epoch, so two different discovery keys can share an epoch number. A contact update therefore accepts a discovery key only if its signed creation time is later, or the same with a higher epoch. The cost is that a rotation signed while the clock was behind stays ignored until a later rotation's time passes the one already stored.

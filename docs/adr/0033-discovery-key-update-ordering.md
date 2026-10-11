# Discovery Key Update Ordering

Restoring an older backup continues from that backup's Epoch, so two different Discovery Keys can share an Epoch number. A contact update therefore accepts a Discovery Key only if its signed creation time is later, or the same with a higher Epoch. The cost is that a rotation signed while the clock was behind stays ignored until a later rotation's time passes the one already stored.

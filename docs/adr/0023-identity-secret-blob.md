# Identity Secret Blob

SecureStorage writes one entry at a time, so separate entries for the Identity Key's two secret halves could end up holding halves from different Identities after an interrupted backup import. So Roost saves both halves as one Identity Secret Blob, and reads no older layout, since no release has promised that stored data survives upgrades.

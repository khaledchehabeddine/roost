# Identity Secret Blob

Both secret halves of the Identity Key are saved together as one Identity Secret Blob in SecureStorage, because SecureStorage writes one entry at a time and two separate entries could end up holding halves from different Identities after an interrupted backup import. The blob's version leaves room for future layouts. Roost reads only this entry, not the two separate entries older builds wrote, since no release has promised that stored data survives upgrades.

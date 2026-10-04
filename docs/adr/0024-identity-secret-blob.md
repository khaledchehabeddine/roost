# Identity Secret Blob

Both secret halves of the Identity Key are saved together as one Identity Secret Blob in SecureStorage. SecureStorage writes one entry at a time, so two separate entries could end up holding halves from different Identities after an interrupted backup import. One entry saves the whole key at once, and its version leaves room for future layouts.

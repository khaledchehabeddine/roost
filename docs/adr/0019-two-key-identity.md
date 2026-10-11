# Two-Key Identity

An Identity has a permanent Identity Key and a rotatable Discovery Key. With one key, Roost would have to choose between rotating the identity, which resets peers' trust, and never rotating prekeys, which weakens forward secrecy. Safety Numbers and Sender Certificates use the Identity Key, which signs the Discovery Key, so rotating the Discovery Key refreshes prekeys while peers keep their trust and Safety Numbers.

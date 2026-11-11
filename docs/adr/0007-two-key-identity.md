# Two-Key Identity

An identity has a permanent identity key and a rotatable discovery key. With one key, changing where peers reach an identity would change the identity too, which resets peers' trust. Safety numbers and sender certificates use the identity key, which signs the discovery key, so an inbox rotation changes where peers reach an identity while they keep their trust and safety numbers.

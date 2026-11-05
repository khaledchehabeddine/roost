# Naming

Many values here share a type, such as public keys and integer times, so only their names tell them apart.

## Names

- Spell out each word in a name, such as `chain_key`, not `ck`, except widely used abbreviations, such as `id`, `len`, and `AEAD`.
- Name similar values by their role, such as `sender_key` and `recipient_key`, not `key1` and `key2`.
- Name a function that returns `bool` as a yes or no question, such as `is_valid_key` or `contains_digest`, not `validate_key`.
- Use `try_` only for a function that fails instead of waiting, such as `try_lock`.
- Name a type for what it holds, such as `PublicExampleKey` for the public half of a key and `ExampleKeyBundle` for several public keys.
- Use `*Manager` for a type that creates, stores, and replaces one kind of item, such as `ExampleKeyManager`.

## Time

- Name a timestamp after the event it records, such as `sent_at`.
- End an integer time variable's name with its unit, such as `created_at_secs`.

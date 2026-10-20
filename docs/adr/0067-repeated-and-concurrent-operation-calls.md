# Repeated and Concurrent Operation Calls

Asking a waiting Message Operation for its next step again returns the same request without repeating cryptography, and calls from two threads take turns. So misuse gives the same result on every run.

## Alternatives

- Fail a call that arrives while another is running: the failure would depend on timing, and it would end the first caller's operation.

# IC COSE chain-key library

Shared Rust implementation used by `ic_cose_canister` and dMsg. It exports no
Candid entry points and owns no namespace, account, authorization, or storage.

- `Operation`: construct once, estimate request + outgoing call fees, persist the
  authorized execution and budget, then consume the operation with `execute`.
- `PublicKey`: retain the public key and chain code for offline child derivation.
- `classify_failure`: preserve unsent, rejected, and unknown outcomes. Never retry
  an unknown outcome by silently issuing another signing or derivation call.
- vetKD accepts exact context/input bytes. Each caller owns its domain encoding.

`Cost` is a conservative call budget: the request payment plus `cost_call`,
including maximum response-transmission and callback-execution reservations.
It is not an actual bill and excludes unrelated instruction, storage and query costs.
`cost_upper_bound` subtracts refunds of attached cycles; it cannot measure the
system's automatic refunds of unused response/callback reservations. A `NotSent`
failure costs zero; do not call `msg_cycles_refunded` in that pre-dispatch case.
Persist request deduplication before awaiting management calls. A consumed Rust
value alone does not provide durable deduplication or exactly-once execution.

---
"@cloudflare/computer": minor
---

The computerd HTTP and WebSocket surfaces now fail closed when
`RPC_CLIENT_SECRET` is unset. Local and harness runs that need
unauthenticated access must set `RPC_ALLOW_ANONYMOUS=1` or
`RPC_ALLOW_ANONYMOUS=all-interfaces`; the former binds only to loopback,
while the latter opens the RPC surface on every interface.

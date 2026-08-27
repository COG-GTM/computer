---
"@cloudflare/computer": minor
---

`POST /connect` now dials only endpoints named at launch. The daemon reads `CONNECT_ALLOWED_ORIGINS` when it starts, defaulting to `http://computer.internal`, and refuses a request whose `base` is not on the list with `403` before it probes anything. The Cloudflare container backend sets the variable to the egress host it serves. Previously the request body chose the endpoint, so anything that could reach the daemon's port — including every command the workspace runs — could point a readiness probe at a host inside the container's network and then have the whole workspace session, file access and command execution, served to an endpoint of its choosing.

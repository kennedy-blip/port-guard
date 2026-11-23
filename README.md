# PortGuard

PortGuard is a Go + Vanilla JavaScript dashboard for **authorized** TCP service reachability checks and exposure triage. It uses Go standard-library networking and ships as one Vercel project.

## Features

- Dark, responsive frontend in `public/` — no TypeScript, Node runtime, or bundler.
- Go serverless handlers at `/api/scan` and `/api/profiles`.
- Concurrent TCP connect checks, per-port latency, service hints, and short printable banner capture.
- Risk labels for expected public web ports, development ports, and exposed data services.
- Reusable seeded and custom scan profiles.
- Offline UI demo data when opened directly from disk.

## Safety boundaries

Use only on systems you own or have explicit written permission to assess. The UI requires an authorization confirmation and the hosted scan handler independently requires `authorized: true`. The hosted scanner rejects private, loopback, link-local, and other non-global targets to prevent use as a private-network or cloud-metadata pivot. Scans are capped at 32 unique ports, 8 concurrent dials, and a 3-second connect timeout. This is a reachability diagnostic, not a vulnerability assessment.

## Local development

Requires Go 1.22+.

```sh
gofmt -w api/profiles/index.go api/scan/index.go
go vet ./api/...
go test ./...
go run ./devserver.go
```

Then open http://localhost:8080. The local development server serves `public/` and exposes the same API paths. Local scanner behavior follows the same public-target policy.

## Deploy to Vercel

1. Import `kennedy-blip/port-guard` into Vercel.
2. Keep the project root as the repository root.
3. Deploy with the Go runtime enabled. Static assets are served from `public/`.
4. No environment variables or secrets are required.

## API

- `GET /api/profiles` — seeded and in-memory custom profiles.
- `POST /api/profiles` — save a profile: `{name,host,ports,timeoutMs,description}`.
- `POST /api/scan` — scan: `{host,ports,timeoutMs,authorized:true}`.

Custom profiles are stored in process memory and may reset between serverless invocations or deployments. Use an external database if durable shared profiles are required.

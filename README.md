# Rocky Linux Errata Frontend

Web frontend for [errata.build.resf.org](https://errata.build.resf.org/), displaying security advisories, bug fixes, and enhancements for Rocky Linux.

## Development

**Prerequisites:** Node.js 20+, Yarn

```bash
yarn install
yarn dev
```

The dev server runs at `http://localhost:9007` and proxies API requests to a local [apollo-server](https://github.com/resf/distro-tools/tree/main/apollo/server) instance at `127.0.0.1:9999`. See the [Apollo Development Guide](https://github.com/resf/distro-tools/blob/main/apollo/README.md#development-guide) for setting up the backend locally.

To proxy to the production API instead, update `vite.config.ts`:

```ts
proxy: {
  "/api": {
    target: "https://errata.build.resf.org",
    changeOrigin: true,
  },
},
```

## Build

```bash
yarn build       # Type-check + Vite production build
yarn typecheck   # Type-check only
```

Output goes to `dist/`.

## Container

The production container uses nginx to serve static assets and proxy `/api` requests to the apollo-server backend.

```bash
docker build -t errata-frontend .
docker run -p 8086:8086 errata-frontend
```

The nginx config (`nginx/default.conf`) proxies `/api` to `apollo-server.apollo2production.svc.cluster.local:8000` by default, which works inside the Kubernetes cluster.

## Deployment

Deploy to Kubernetes with Helm:

```bash
# First deploy
helm install errata-frontend deploy/helm/ \
  -n <namespace> \
  --set image.tag=<image-tag>

# Updates
helm upgrade errata-frontend deploy/helm/ \
  -n <namespace> \
  --set image.tag=<new-image-tag>

# Rollback
helm rollback errata-frontend <revision> -n <namespace>
```

Production values override: `deploy/helm/values-production.yaml`

## Architecture

- **Framework:** React 18, TypeScript, Chakra UI v2, Tailwind CSS
- **Build:** Vite
- **Production server:** nginx (static files + reverse proxy)
- **API:** Proxies to [apollo-server](https://github.com/resf/distro-tools/tree/main/apollo/server) V2 compatibility API
- **CI:** GitHub Actions builds and pushes to `ghcr.io/rocky-linux/errata-frontend`

## Public tracker

`/` is the advisory index: search, filters, and the newest Rocky Linux errata. The header sections are:

- **Advisories** (`/`, `/:id`) — the advisory list and permalink. `/advisories` redirects to `/`. `/fixes` remains the tracker advisory catalog
- **CVEs** (`/cves`, `/cves/CVE-…`) — searchable Rocky CVE rows and one CVE’s release status, description, and fixing advisories
- **Data Feeds / API** (`/feeds`) — CSV, JSON, RSS, CSAF, OVAL, and the read-only MCP setup. `/about` redirects home

`/packages` remains the source-package catalog (latest advisory-derived source version, advisory counts, EOL). It is not in the primary navigation. `/technologies` redirects there. An advisory search stays on the advisory list and also matches a CVE or package name; links on that row open the same query in CVEs or Packages. Filters live in the URL. The read-only tracker MCP is `POST https://errata.research.atomicorp.com/mcp` (100 requests per minute per IP).

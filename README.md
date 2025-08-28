# CyberScan Dashboard

A Next.js + TypeScript implementation of a cybersecurity tools dashboard. It showcases sample tools such as Nmap, SQLMap, OSINT, and Web scanning, along with recent scan results and summary charts.

## Features

- Dashboard of security tools
- Recent scan results table
- Summary charts built with Chart.js

See [docs/PROMISES_TO_FEATURES.md](docs/PROMISES_TO_FEATURES.md) for the mapping of promises to implemented features. Architectural trade-offs are captured in [docs/DECISIONS.md](docs/DECISIONS.md).

## Getting Started

### Prerequisites
- Node.js 20
- pnpm
- (for live scanning) system tools: `nmap`, `sqlmap`, `whois`, `curl`
  - install on Debian/Ubuntu via `apt-get install nmap sqlmap`
  - set `USE_MOCKS=false` to enable live scans

### Installation
```sh
pnpm install
```

### Development
```sh
pnpm dev
```

### Testing
```sh
pnpm test
```

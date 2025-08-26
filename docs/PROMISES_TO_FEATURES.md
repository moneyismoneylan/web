# Promises to Features

This document maps user-facing promises to concrete deliverables with enough detail to test and validate each feature.

| Promise | Feature | User Story | Acceptance Criteria | API/Data Contract | UX States | Manual Validation Steps | Automated Tests |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dashboard listing security tools (Nmap, SQLMap, OSINT, Web Scan) | Tool cards on the dashboard | As a security analyst, I can quickly see available tools to launch scans. | Four cards display titles and descriptions; clicking a card triggers a start alert. | Static list of `{ title: string, description: string }`. | Default, hover, focus. | Open home page and click each card to see alert. | [tests/unit/home.test.tsx](../tests/unit/home.test.tsx) |
| Display recent scan results | Table of recent scans in the "Scan Results" section | As a user, I review latest scan output at a glance. | Table shows rows with tool, target, time, and status. | Array of `{ tool: string, target: string, time: string, status: string }`. | Loading (future), populated, empty (future). | Open home page and verify rows render in table. | [tests/unit/home.test.tsx](../tests/unit/home.test.tsx) |
| Provide summary reports | Charts for scan statistics and vulnerability distribution | As a user, I visualise scan trends and vulnerability levels. | Line chart shows monthly counts; doughnut chart shows severity distribution. | `{ labels: string[], datasets: { label: string, data: number[] }[] }` | Loading (future), populated. | Open home page and verify both charts display. | [tests/unit/home.test.tsx](../tests/unit/home.test.tsx) |


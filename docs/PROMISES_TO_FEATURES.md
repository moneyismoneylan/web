# Promises to Features

This document maps promises found in the project to concrete features and acceptance criteria.

| Promise | Feature | Acceptance Criteria | Testability |
| --- | --- | --- | --- |
| Dashboard listing security tools (Nmap, SQLMap, OSINT, Web Scan) | Tool cards on the dashboard | Each card is visible with title and description. Clicking a card shows an alert. | tests/unit/home.test.tsx |
| Display recent scan results | Table of recent scans in the "Scan Results" section | Table renders rows with tool name, target, time, and status | tests/unit/home.test.tsx |
| Provide summary reports | Charts for scan statistics and vulnerability distribution | Charts render using Chart.js with sample data | Manual: charts appear when page loads |

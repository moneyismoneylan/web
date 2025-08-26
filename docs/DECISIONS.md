# Decision Log

This log records major technical decisions for the project.

| Date | Decision | Context | Alternatives | Outcome |
| --- | --- | --- | --- | --- |
| 2024-07-24 | Adopt Next.js App Router with TypeScript | Need a full-stack React framework with SSR and file-based routing. | Remix, Astro | Next.js offers built-in routing, API routes, and strong community support. |
| 2024-07-24 | Style with Tailwind CSS | Rapid prototyping with utility classes. | CSS Modules, styled-components | Tailwind provides a small bundle and consistent design system. |
| 2024-07-24 | Manage packages with pnpm | Efficient, deterministic installs. | npm, yarn | pnpm's disk efficiency and speed suit monorepos and CI. |
| 2024-07-24 | Charts via Chart.js wrapped with react-chartjs-2 | Need lightweight charting for summary views. | Recharts, ECharts | Chart.js is small and integrates well with React via react-chartjs-2. |


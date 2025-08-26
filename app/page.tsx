import ToolCard from '../components/ToolCard';
import ScanResultsTable from '../components/ScanResultsTable';
import SummaryCharts from '../components/SummaryCharts';
import { getDictionary } from '../lib/i18n';

const dict = getDictionary('en');

export default function HomePage() {
  return (
    <main className="p-4 space-y-8">
      <h1 className="text-3xl font-bold">{dict.dashboard}</h1>
      <section>
        <h2 className="text-2xl font-semibold mb-4">{dict.tools}</h2>
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-4">
          <ToolCard title="Nmap" description="Network scanning" />
          <ToolCard title="SQLMap" description="SQL injection detection" />
          <ToolCard title="OSINT" description="Open source intelligence" />
          <ToolCard title="Web Scan" description="Basic web vulnerability scan" />
        </div>
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-4">{dict.recentScanResults}</h2>
        <ScanResultsTable />
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-4">{dict.summary}</h2>
        <SummaryCharts />
      </section>
    </main>
  );
}

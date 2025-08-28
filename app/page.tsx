import ToolCard from '../components/ToolCard';
import ScanResultsTable from '../components/ScanResultsTable';
import SummaryCharts from '../components/SummaryCharts';
import { getDictionary } from '../lib/i18n';

const dict = getDictionary('en');

export default function HomePage() {
  return (
    <div className="space-y-12">
      <h1 className="text-3xl font-bold">{dict.dashboard}</h1>
      <section>
        <h2 className="text-2xl font-semibold mb-6">{dict.tools}</h2>
        <div className="grid gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
          <ToolCard tool="nmap" title="Nmap" description="Network scanning" icon="📡" />
          <ToolCard
            tool="sqlmap"
            title="SQLMap"
            description="SQL injection detection"
            icon="🛢️"
          />
          <ToolCard
            tool="osint"
            title="OSINT"
            description="Open source intelligence"
            icon="🕵️"
          />
          <ToolCard
            tool="web"
            title="Web Scan"
            description="Basic web vulnerability scan"
            icon="🌐"
          />
        </div>
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-6">{dict.recentScanResults}</h2>
        <ScanResultsTable />
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-6">{dict.summary}</h2>
        <SummaryCharts />
      </section>
    </div>
  );
}

import ToolCard from '@/components/ToolCard';
import ScanResultsTable from '@/components/ScanResultsTable';
import SummaryCharts from '@/components/SummaryCharts';

export default function DashboardPage() {
  return (
    <main className="p-4 space-y-8">
      <h1 className="text-3xl font-bold">Dashboard</h1>
      <section>
        <h2 className="text-2xl font-semibold mb-4">Tools</h2>
        <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-4">
          <ToolCard tool="nmap" title="Nmap" description="Network scanning" />
          <ToolCard tool="sqlmap" title="SQLMap" description="SQL injection detection" />
          <ToolCard tool="osint" title="OSINT" description="Open source intelligence" />
          <ToolCard tool="web" title="Web Scan" description="Basic web vulnerability scan" />
        </div>
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-4">Recent Scans</h2>
        <ScanResultsTable />
      </section>
      <section>
        <h2 className="text-2xl font-semibold mb-4">Summary</h2>
        <SummaryCharts />
      </section>
    </main>
  );
}

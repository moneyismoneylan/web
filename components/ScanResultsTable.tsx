'use client';

const sampleData = [
  { tool: 'Nmap', target: '192.168.1.1', time: '2024-01-01', status: 'Completed' },
  { tool: 'SQLMap', target: 'example.com', time: '2024-01-02', status: 'Running' },
];

export default function ScanResultsTable() {
  return (
    <table className="min-w-full text-sm">
      <thead>
        <tr className="text-left">
          <th className="p-2">Tool</th>
          <th className="p-2">Target</th>
          <th className="p-2">Time</th>
          <th className="p-2">Status</th>
        </tr>
      </thead>
      <tbody>
        {sampleData.map((row, idx) => (
          <tr key={idx} className="border-t border-gray-700">
            <td className="p-2">{row.tool}</td>
            <td className="p-2">{row.target}</td>
            <td className="p-2">{row.time}</td>
            <td className="p-2">{row.status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

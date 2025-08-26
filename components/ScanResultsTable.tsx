'use client';

import { useState } from 'react';
import { useScans } from '@/lib/api';
import { exportCSV, exportJSON } from '@/lib/export';

export default function ScanResultsTable() {
  const { data = [], isLoading, error } = useScans();
  const [filter, setFilter] = useState('');
  const [sortAsc, setSortAsc] = useState(true);
  const [page, setPage] = useState(0);
  const pageSize = 5;

  const filtered = data.filter((d) => d.target.includes(filter));
  const sorted = [...filtered].sort((a, b) =>
    sortAsc ? a.tool.localeCompare(b.tool) : b.tool.localeCompare(a.tool)
  );
  const paginated = sorted.slice(page * pageSize, (page + 1) * pageSize);

  if (isLoading) return <p>Loading...</p>;
  if (error) return <p>Error loading scans</p>;

  return (
    <div>
      <div className="flex items-center mb-2 gap-2">
        <input
          className="rounded bg-gray-700 p-2 text-white"
          placeholder="Filter by target"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button className="bg-blue-600 px-2 py-1 rounded" onClick={() => exportCSV('scans.csv', filtered as any)}>
          CSV
        </button>
        <button className="bg-blue-600 px-2 py-1 rounded" onClick={() => exportJSON('scans.json', filtered)}>
          JSON
        </button>
      </div>
      <table className="min-w-full text-sm">
        <thead>
          <tr className="text-left">
            <th className="p-2 cursor-pointer" onClick={() => setSortAsc(!sortAsc)}>
              Tool
            </th>
            <th className="p-2">Target</th>
            <th className="p-2">Time</th>
            <th className="p-2">Status</th>
          </tr>
        </thead>
        <tbody>
          {paginated.map((row) => (
            <tr key={row.id} className="border-t border-gray-700">
              <td className="p-2">{row.tool}</td>
              <td className="p-2">{row.target}</td>
              <td className="p-2">{row.startedAt}</td>
              <td className="p-2">{row.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-2 flex justify-between">
        <button disabled={page === 0} onClick={() => setPage((p) => Math.max(p - 1, 0))}>
          Prev
        </button>
        <button
          disabled={(page + 1) * pageSize >= filtered.length}
          onClick={() => setPage((p) => p + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

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
    <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-4 shadow">
      <div className="flex flex-wrap items-center mb-4 gap-2">
        <input
          className="flex-1 rounded bg-gray-700 p-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Filter by target"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <button
          className="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded"
          onClick={() => exportCSV('scans.csv', filtered as any)}
        >
          CSV
        </button>
        <button
          className="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded"
          onClick={() => exportJSON('scans.json', filtered)}
        >
          JSON
        </button>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="text-left bg-gray-700">
              <th
                className="p-2 cursor-pointer select-none"
                onClick={() => setSortAsc(!sortAsc)}
              >
                Tool
              </th>
              <th className="p-2">Target</th>
              <th className="p-2">Time</th>
              <th className="p-2">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {paginated.map((row) => (
              <tr key={row.id}>
                <td className="p-2 capitalize">{row.tool}</td>
                <td className="p-2 break-all">{row.target}</td>
                <td className="p-2">{row.startedAt}</td>
                <td className="p-2">{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex justify-between">
        <button
          className="px-3 py-1 rounded bg-gray-700 disabled:opacity-50"
          disabled={page === 0}
          onClick={() => setPage((p) => Math.max(p - 1, 0))}
        >
          Prev
        </button>
        <button
          className="px-3 py-1 rounded bg-gray-700 disabled:opacity-50"
          disabled={(page + 1) * pageSize >= filtered.length}
          onClick={() => setPage((p) => p + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
}

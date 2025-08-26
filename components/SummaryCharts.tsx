'use client';

import {
  Chart,
  BarElement,
  CategoryScale,
  LinearScale,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Bar, Doughnut } from 'react-chartjs-2';
import { useSummary } from '@/lib/api';

Chart.register(BarElement, CategoryScale, LinearScale, ArcElement, Tooltip, Legend);

export default function SummaryCharts() {
  const { data, isLoading, error } = useSummary();
  if (isLoading) return <p>Loading...</p>;
  if (error || !data) return <p>Error loading summary</p>;

  const barData = {
    labels: Object.keys(data.byTool),
    datasets: [
      {
        label: 'Scans by Tool',
        data: Object.values(data.byTool),
        backgroundColor: 'rgba(13,110,253,0.5)',
      },
    ],
  };

  const doughnutData = {
    labels: ['Completed', 'Running', 'Failed'],
    datasets: [
      {
        data: [data.completed, data.running, data.failed],
        backgroundColor: [
          'rgb(25,135,84)',
          'rgb(13,110,253)',
          'rgb(220,53,69)',
        ],
      },
    ],
  };

  return (
    <div className="grid gap-8 md:grid-cols-2">
      <Bar
        data={barData}
        options={{
          plugins: { legend: { labels: { color: '#fff' } } },
          scales: {
            x: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
            y: { ticks: { color: '#fff' }, grid: { color: 'rgba(255,255,255,0.1)' } },
          },
        }}
      />
      <Doughnut data={doughnutData} options={{ plugins: { legend: { labels: { color: '#fff' } } } }} />
    </div>
  );
}

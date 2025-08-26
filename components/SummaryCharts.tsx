'use client';

import {
  Chart,
  LineElement,
  PointElement,
  CategoryScale,
  LinearScale,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Line, Doughnut } from 'react-chartjs-2';

Chart.register(LineElement, PointElement, CategoryScale, LinearScale, ArcElement, Tooltip, Legend);

export default function SummaryCharts() {
  const lineData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
    datasets: [
      {
        label: 'Completed',
        data: [12, 19, 15, 17, 22, 25, 30],
        borderColor: 'rgb(25, 135, 84)',
        backgroundColor: 'rgba(25, 135, 84, 0.2)',
      },
      {
        label: 'Running',
        data: [5, 8, 6, 9, 7, 10, 8],
        borderColor: 'rgb(13, 110, 253)',
        backgroundColor: 'rgba(13, 110, 253, 0.2)',
      },
    ],
  };

  const doughnutData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [3, 7, 12, 8],
        backgroundColor: [
          'rgb(220, 53, 69)',
          'rgb(255, 193, 7)',
          'rgb(13, 202, 240)',
          'rgb(25, 135, 84)',
        ],
      },
    ],
  };

  return (
    <div className="grid gap-8 md:grid-cols-2">
      <Line
        data={lineData}
        options={{
          responsive: true,
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

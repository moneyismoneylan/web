'use client';

import { useState } from 'react';
import { useRunTool } from '@/lib/api';
import type { Tool } from '@/lib/types';

interface ToolCardProps {
  tool: Tool;
  title: string;
  description: string;
  icon?: string;
}

export default function ToolCard({ tool, title, description, icon }: ToolCardProps) {
  const [target, setTarget] = useState('');
  const runTool = useRunTool();

  const handleClick = () => {
    runTool.mutate({ tool, target });
  };

  return (
    <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-6 shadow hover:shadow-lg transition hover:-translate-y-1 focus-within:ring-2 focus-within:ring-blue-500">
      <div className="flex items-center mb-3">
        {icon && <span className="text-3xl mr-2" aria-hidden>{icon}</span>}
        <h3 className="text-xl font-semibold">{title}</h3>
      </div>
      <p className="text-sm text-gray-300 mb-4">{description}</p>
      <div className="flex gap-2">
        <input
          className="flex-1 rounded bg-gray-700 p-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Target"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <button
          onClick={handleClick}
          className="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded font-medium"
        >
          Run
        </button>
      </div>
    </div>
  );
}

'use client';

import { useState } from 'react';
import { useRunTool } from '@/lib/api';
import type { Tool } from '@/lib/types';

interface ToolCardProps {
  tool: Tool;
  title: string;
  description: string;
}

export default function ToolCard({ tool, title, description }: ToolCardProps) {
  const [target, setTarget] = useState('');
  const runTool = useRunTool();

  const handleClick = () => {
    runTool.mutate({ tool, target });
  };

  return (
    <div className="tool-card bg-gray-800 rounded-lg p-4 text-left focus-within:ring-2 focus-within:ring-blue-500">
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p className="text-sm text-gray-300 mb-2">{description}</p>
      <input
        className="w-full mb-2 rounded bg-gray-700 p-2 text-white"
        placeholder="Target"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />
      <button
        onClick={handleClick}
        className="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded"
      >
        Run
      </button>
    </div>
  );
}

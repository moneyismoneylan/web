'use client';
import React from 'react';

interface Props {
  data: unknown;
  error?: string;
}

export function ResultCard({ data, error }: Props) {
  if (error) {
    return <div className="p-4 bg-red-800 text-red-100 rounded">{error}</div>;
  }
  if (!data) {
    return <div className="p-4 text-gray-400">No result</div>;
  }
  return (
    <pre className="p-4 bg-gray-800 text-sm text-gray-100 rounded overflow-auto">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

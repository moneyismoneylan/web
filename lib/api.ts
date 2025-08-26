'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Scan, ScanResult, SummaryStats, Tool } from './types';

export function useScans() {
  return useQuery<Scan[]>({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans');
      if (!res.ok) throw new Error('Failed to fetch scans');
      return res.json();
    },
  });
}

export function useRunTool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: { tool: Tool; target: string; options?: Record<string, unknown> }) => {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      if (!res.ok) throw new Error('Failed to start scan');
      return res.json() as Promise<{ scanId: string }>;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['summary'] });
    },
  });
}

export function useScan(id: string) {
  return useQuery<ScanResult>({
    queryKey: ['scan', id],
    queryFn: async () => {
      const res = await fetch(`/api/scans/${id}`);
      if (!res.ok) throw new Error('Failed to fetch scan');
      return res.json();
    },
    enabled: !!id,
  });
}

export function useSummary() {
  return useQuery<SummaryStats>({
    queryKey: ['summary'],
    queryFn: async () => {
      const res = await fetch('/api/summary');
      if (!res.ok) throw new Error('Failed to fetch summary');
      return res.json();
    },
  });
}

import { render, screen } from '@testing-library/react';
import React from 'react';
import HomePage from '../../app/page';
import { Providers } from '../../app/providers';

vi.mock('react-chartjs-2', () => ({
  Bar: () => <div data-testid="bar-chart" />,
  Doughnut: () => <div data-testid="doughnut-chart" />,
}));

vi.mock('../../lib/api', () => ({
  useScans: () => ({
    data: [
      { id: '1', tool: 'nmap', target: '192.168.1.1', startedAt: '2024-01-01', status: 'completed' },
    ],
    isLoading: false,
    error: null,
  }),
  useRunTool: () => ({ mutate: vi.fn() }),
  useSummary: () => ({
    data: {
      total: 1,
      completed: 1,
      running: 0,
      failed: 0,
      byTool: { nmap: 1, sqlmap: 0, osint: 0, web: 0 },
    },
    isLoading: false,
    error: null,
  }),
}));

describe('HomePage', () => {
  it('renders heading', () => {
    render(
      <Providers>
        <HomePage />
      </Providers>
    );
    expect(
      screen.getByRole('heading', { level: 1, name: /cyberscan dashboard/i })
    ).toBeInTheDocument();
  });

  it('lists all tool cards', () => {
    render(
      <Providers>
        <HomePage />
      </Providers>
    );
    const tools = ['Nmap', 'SQLMap', 'OSINT', 'Web Scan'];
    tools.forEach((tool) => {
      expect(screen.getAllByText(new RegExp(tool, 'i'))[0]).toBeInTheDocument();
    });
  });

  it('shows recent scan results', () => {
    render(
      <Providers>
        <HomePage />
      </Providers>
    );
    expect(screen.getByRole('cell', { name: /192\.168\.1\.1/ })).toBeInTheDocument();
  });

  it('renders summary charts', () => {
    render(
      <Providers>
        <HomePage />
      </Providers>
    );
    expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    expect(screen.getByTestId('doughnut-chart')).toBeInTheDocument();
  });
});

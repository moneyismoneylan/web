import { render, screen } from '@testing-library/react';
import HomePage from '../../app/page';
import React from 'react';

vi.mock('react-chartjs-2', () => ({
  Line: () => <div>line</div>,
  Doughnut: () => <div>doughnut</div>,
}));

describe('HomePage', () => {
  it('renders heading', () => {
    render(<HomePage />);
    expect(screen.getByRole('heading', { level: 1, name: /cyberscan dashboard/i })).toBeInTheDocument();
  });
});

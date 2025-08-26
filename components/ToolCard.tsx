'use client';

interface ToolCardProps {
  title: string;
  description: string;
}

export default function ToolCard({ title, description }: ToolCardProps) {
  const handleClick = () => {
    alert(`${title} tool starting...`);
  };

  return (
    <button
      onClick={handleClick}
      className="tool-card bg-gray-800 rounded-lg p-4 text-left hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
    >
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p className="text-sm text-gray-300">{description}</p>
    </button>
  );
}

import clsx from 'clsx';

const COLORS: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-400 border-red-800',
  high:     'bg-orange-900/40 text-orange-400 border-orange-800',
  medium:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
  low:      'bg-blue-900/40 text-blue-400 border-blue-800',
  info:     'bg-gray-800 text-gray-400 border-gray-700',
  blocked:  'bg-red-900/40 text-red-400 border-red-800',
  allowed:  'bg-green-900/40 text-green-400 border-green-800',
  flagged:  'bg-yellow-900/40 text-yellow-400 border-yellow-800',
  requires_approval: 'bg-purple-900/40 text-purple-400 border-purple-800',
};

export default function RiskBadge({ value }: { value: string }) {
  const key = value?.toLowerCase() ?? 'info';
  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium', COLORS[key] ?? COLORS.info)}>
      {value}
    </span>
  );
}

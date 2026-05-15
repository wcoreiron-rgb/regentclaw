import clsx from 'clsx';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  color?: 'indigo' | 'red' | 'orange' | 'green' | 'yellow';
  sub?: string;
}

const colorMap = {
  indigo: 'text-indigo-400 bg-indigo-900/30',
  red:    'text-red-400 bg-red-900/30',
  orange: 'text-orange-400 bg-orange-900/30',
  green:  'text-green-400 bg-green-900/30',
  yellow: 'text-yellow-400 bg-yellow-900/30',
};

export default function StatCard({ label, value, icon: Icon, color = 'indigo', sub }: StatCardProps) {
  return (
    <div
      className="rounded-xl border p-5 flex items-start gap-4"
      style={{ background: 'var(--rc-bg-surface)', borderColor: 'var(--rc-border)' }}
    >
      <div className={clsx('p-2.5 rounded-lg flex-shrink-0', colorMap[color])}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>{label}</p>
        <p className="text-2xl font-bold mt-0.5" style={{ color: 'var(--rc-text-1)' }}>{value}</p>
        {sub && <p className="text-xs mt-1" style={{ color: 'var(--rc-text-3)' }}>{sub}</p>}
      </div>
    </div>
  );
}

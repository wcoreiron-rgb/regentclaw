'use client';
/**
 * ClientDate — renders locale-formatted dates only after hydration.
 *
 * Why: Next.js SSR renders on the server (UTC) then hydrates on the client
 * (local timezone). toLocaleString/toLocaleTimeString produce different output
 * in each environment, causing React hydration mismatches.
 *
 * Usage:
 *   <ClientDate value={row.timestamp} />
 *   <ClientDate value={row.timestamp} format="time" />
 *   <ClientDate value={row.timestamp} format="date" />
 *   <ClientDate value={row.timestamp} fallback="pending" />
 */
import { useEffect, useState } from 'react';

type Props = {
  value: string | Date | null | undefined;
  format?: 'datetime' | 'time' | 'date';
  fallback?: string;
  className?: string;
};

export default function ClientDate({ value, format = 'datetime', fallback = '—', className }: Props) {
  const [text, setText] = useState<string | null>(null);

  useEffect(() => {
    if (!value) { setText(fallback); return; }
    const d = value instanceof Date ? value : new Date(value);
    if (isNaN(d.getTime())) { setText(fallback); return; }
    switch (format) {
      case 'time':     setText(d.toLocaleTimeString()); break;
      case 'date':     setText(d.toLocaleDateString()); break;
      default:         setText(d.toLocaleString()); break;
    }
  }, [value, format, fallback]);

  // Render a stable placeholder until client-side hydration is complete
  return <span className={className}>{text ?? '…'}</span>;
}

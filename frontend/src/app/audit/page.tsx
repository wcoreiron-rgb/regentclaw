'use client';
import { useEffect, useState } from 'react';
import { ScrollText } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { getAuditLogs } from '@/lib/api';
import ClientDate from '@/components/ClientDate';

export default function AuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [complianceOnly, setComplianceOnly] = useState(false);

  useEffect(() => {
    getAuditLogs(complianceOnly).then(setLogs).catch(console.error);
  }, [complianceOnly]);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <ScrollText className="text-cyan-400" /> Audit Log
          </h1>
          <p className="text-gray-400 mt-1">Full traceability — every action, decision, and policy evaluation</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={complianceOnly} onChange={e => setComplianceOnly(e.target.checked)} className="rounded" />
          <span className="text-sm text-gray-400">Compliance-relevant only</span>
        </label>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Timestamp</th>
                <th className="px-6 py-3 text-left">Actor</th>
                <th className="px-6 py-3 text-left">Action</th>
                <th className="px-6 py-3 text-left">Resource</th>
                <th className="px-6 py-3 text-left">Outcome</th>
                <th className="px-6 py-3 text-left">Module</th>
                <th className="px-6 py-3 text-left">Frameworks</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {logs.length === 0 && (
                <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500">No audit logs yet.</td></tr>
              )}
              {logs.map((l: any) => (
                <tr key={l.id} className="hover:bg-gray-800/50">
                  <td className="px-6 py-3 text-gray-500 text-xs whitespace-nowrap"><ClientDate value={l.timestamp} /></td>
                  <td className="px-6 py-3 text-white">{l.actor}</td>
                  <td className="px-6 py-3 text-gray-300">{l.action}</td>
                  <td className="px-6 py-3 text-gray-400">{l.resource_name ?? l.resource_type ?? '—'}</td>
                  <td className="px-6 py-3"><RiskBadge value={l.outcome} /></td>
                  <td className="px-6 py-3 text-regent-400">{l.module ?? '—'}</td>
                  <td className="px-6 py-3 text-xs text-gray-500">{l.frameworks ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

'use client';
import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Play, CheckCircle, XCircle, Clock, RefreshCw,
  ChevronRight, Activity, Zap, Bot,
} from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { getRecentRuns } from '@/lib/api';
import ClientDate from '@/components/ClientDate';

export default function RunsPage() {
  const [runs, setRuns]     = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await getRecentRuns(50).catch(() => []);
      setRuns(r ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const statusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'failed':    return <XCircle className="w-4 h-4 text-red-400" />;
      case 'running':   return <RefreshCw className="w-4 h-4 text-blue-400 animate-spin" />;
      default:          return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Activity className="text-cyan-400" /> Run History
          </h1>
          <p className="text-gray-400 mt-1">All workflow executions — click any run to open the Flight Recorder</p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white">Recent Executions</h2>
          <span className="text-xs text-gray-500">{runs.length} runs</span>
        </div>
        {runs.length === 0 ? (
          <p className="px-6 py-8 text-gray-500 text-sm">No workflow runs yet. Trigger a workflow to see execution history here.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-6 py-3 text-left">Status</th>
                <th className="px-6 py-3 text-left">Workflow</th>
                <th className="px-6 py-3 text-left">Triggered By</th>
                <th className="px-6 py-3 text-left">Started</th>
                <th className="px-6 py-3 text-left">Duration</th>
                <th className="px-6 py-3 text-left">Steps</th>
                <th className="px-6 py-3 text-left">Replay</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {runs.map((r: any) => (
                <tr key={r.run_id} className="hover:bg-gray-800/50 cursor-pointer"
                    onClick={() => router.push(`/runs/${r.run_id}`)}>
                  <td className="px-6 py-3 flex items-center gap-2">
                    {statusIcon(r.status)}
                    <RiskBadge value={r.status} />
                  </td>
                  <td className="px-6 py-3 text-white font-medium">{r.workflow_name}</td>
                  <td className="px-6 py-3 text-gray-400 text-xs">{r.triggered_by}</td>
                  <td className="px-6 py-3 text-gray-400 text-xs">
                    <ClientDate value={r.started_at} fallback="—" />
                  </td>
                  <td className="px-6 py-3 text-gray-400 text-xs">
                    {r.duration_sec != null ? `${r.duration_sec.toFixed(1)}s` : '—'}
                  </td>
                  <td className="px-6 py-3 text-xs">
                    <span className="text-green-400">{r.steps_completed} ok</span>
                    {r.steps_failed > 0 && <span className="text-red-400 ml-2">{r.steps_failed} fail</span>}
                  </td>
                  <td className="px-6 py-3">
                    <button className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
                      <Play className="w-3 h-3" /> Replay
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

'use client';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, ChevronLeft, Clock, RefreshCw, ShieldAlert, StopCircle, XCircle } from 'lucide-react';
import RiskBadge from '@/components/RiskBadge';
import { approveSwarmJob, cancelSwarmJob, getSwarmJob, getSwarmTasks } from '@/lib/api';

function statusMeta(status: string) {
  const s = (status || '').toLowerCase();
  if (s === 'completed') return { icon: CheckCircle2, color: 'text-green-400' };
  if (s === 'running') return { icon: RefreshCw, color: 'text-blue-400' };
  if (s === 'failed' || s === 'blocked') return { icon: XCircle, color: 'text-red-400' };
  if (s === 'requires_approval') return { icon: ShieldAlert, color: 'text-yellow-400' };
  return { icon: Clock, color: 'text-gray-400' };
}

function secureChannelMeta(outputJson?: string | null): string {
  if (!outputJson) return '—';
  try {
    const parsed = JSON.parse(outputJson);
    const channel = parsed?.secure_channel;
    if (!channel || channel.enabled !== true) return 'disabled';
    return channel.status || 'enabled';
  } catch {
    return '—';
  }
}

export default function SwarmJobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<any>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const [j, t] = await Promise.all([getSwarmJob(id), getSwarmTasks(id)]);
      setJob(j);
      setTasks(t);
    } catch (e: any) {
      setError(e?.message || 'Failed to load swarm job');
    } finally {
      setLoading(false);
    }
  }, [id]);

useEffect(() => { load(); }, [load]);

  const cancelJob = async () => {
    if (!id) return;
    setBusy(true);
    try { await cancelSwarmJob(id); await load(); } finally { setBusy(false); }
  };

  const approveJob = async () => {
    if (!id) return;
    setBusy(true);
    try { await approveSwarmJob(id); await load(); } finally { setBusy(false); }
  };

  if (loading) {
    return <div className="h-64 flex items-center justify-center"><RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" /></div>;
  }

  if (error || !job) {
    return (
      <div className="space-y-4">
        <Link href="/swarm" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1"><ChevronLeft className="w-4 h-4" /> Back to Swarm</Link>
        <div className="rounded-xl border border-red-900 bg-red-950/30 p-4 text-red-300 text-sm">{error || 'Swarm job not found'}</div>
      </div>
    );
  }

  const meta = statusMeta(job.status);
  const Icon = meta.icon;
  let summary: any = null;
  try { summary = job.result_json ? JSON.parse(job.result_json) : null; } catch { summary = null; }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3">
        <div>
          <Link href="/swarm" className="text-sm text-gray-400 hover:text-white inline-flex items-center gap-1"><ChevronLeft className="w-4 h-4" /> Back to Swarm</Link>
          <h1 className="text-3xl font-bold text-white mt-2">{job.name}</h1>
          <p className="text-gray-400 mt-1">{job.profile} · {job.classification}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="px-3 py-2 rounded-lg border border-gray-700 bg-gray-900 text-gray-200 text-sm hover:bg-gray-800">
            <RefreshCw className="w-4 h-4 inline mr-1" /> Refresh
          </button>
          <button onClick={cancelJob} disabled={busy || ['completed', 'failed', 'cancelled'].includes(job.status)} className="px-3 py-2 rounded-lg border border-gray-700 text-gray-200 text-sm disabled:opacity-50">
            <StopCircle className="w-4 h-4 inline mr-1" /> Cancel
          </button>
          <button onClick={approveJob} disabled={busy || job.status !== 'requires_approval'} className="px-3 py-2 rounded-lg border border-green-700 text-green-300 text-sm disabled:opacity-50">
            <CheckCircle2 className="w-4 h-4 inline mr-1" /> Approve
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card label="Status"><span className={`inline-flex items-center gap-1 ${meta.color}`}><Icon className={`w-4 h-4 ${job.status === 'running' ? 'animate-spin' : ''}`} /> {job.status}</span></Card>
        <Card label="Severity"><RiskBadge value={job.overall_severity || 'info'} /></Card>
        <Card label="Confidence">{job.confidence ?? '—'}</Card>
        <Card label="Parallelism">{job.parallelism}</Card>
        <Card label="Tasks">{String(tasks.length)}</Card>
      </div>

      {summary?.executive_summary && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-white font-semibold">Judge Summary</h2>
          <p className="text-sm text-gray-300 mt-2 leading-relaxed">{summary.executive_summary}</p>
        </div>
      )}

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-white font-semibold">Tasks</h2>
        </div>
        {tasks.length === 0 ? (
          <p className="px-5 py-6 text-sm text-gray-500">No tasks attached to this job.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[920px] text-sm">
              <thead className="text-xs text-gray-500 border-b border-gray-800">
                <tr>
                  <th className="px-5 py-3 text-left">Claw</th>
                  <th className="px-5 py-3 text-left">Task Type</th>
                  <th className="px-5 py-3 text-left">Status</th>
                  <th className="px-5 py-3 text-left">Severity</th>
                  <th className="px-5 py-3 text-left">Confidence</th>
                  <th className="px-5 py-3 text-left">Risk</th>
                  <th className="px-5 py-3 text-left">Secure Channel</th>
                  <th className="px-5 py-3 text-left">Exec Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {tasks.map((task) => {
                  const tMeta = statusMeta(task.status);
                  const TIcon = tMeta.icon;
                  const secureState = secureChannelMeta(task.output_json);
                  return (
                    <tr key={task.id} className="hover:bg-gray-800/40">
                      <td className="px-5 py-3 text-white">{task.claw}</td>
                      <td className="px-5 py-3 text-gray-400">{task.task_type}</td>
                      <td className="px-5 py-3"><span className={`inline-flex items-center gap-1 ${tMeta.color}`}><TIcon className="w-4 h-4" /> {task.status}</span></td>
                      <td className="px-5 py-3"><RiskBadge value={task.severity || 'info'} /></td>
                      <td className="px-5 py-3 text-gray-300">{task.confidence ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{task.risk_score ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-300">{secureState}</td>
                      <td className="px-5 py-3 text-gray-400">{task.execution_time_ms != null ? `${task.execution_time_ms}ms` : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function Card({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
      <p className="text-xs text-gray-500">{label}</p>
      <div className="text-white font-semibold mt-1">{children}</div>
    </div>
  );
}

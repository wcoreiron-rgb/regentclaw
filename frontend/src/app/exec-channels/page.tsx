'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Shield, Terminal, Globe, Key, Factory, CheckCircle, XCircle,
  Clock, RefreshCw, Play, ThumbsUp, ThumbsDown, AlertTriangle,
  Lock, Users, Activity, ChevronDown, ChevronRight,
} from 'lucide-react';
import {
  getExecRequests, getExecStats, getProductionGates, getCredentials,
  submitShellExec, approveExecRequest, rejectExecRequest, executeExecRequest,
  approveProductionGate, rejectProductionGate, executeProductionGate, rollbackProductionGate,
} from '@/lib/api';

// ─── types ───────────────────────────────────────────────────────────────────

type ExecReq = {
  id:               string;
  channel:          string;
  requested_by:     string;
  command:          string;
  environment:      string;
  justification:    string;
  trust_score:      number;
  risk_level:       string;
  policy_decision:  string;
  policy_flags:     string[];
  requires_approval: boolean;
  approval_count:   number;
  status:           string;
  exit_code:        number | null;
  stdout:           string;
  output_summary:   string;
  duration_ms:      number;
  created_at:       string;
};

type ProdGate = {
  id:                 string;
  title:              string;
  description:        string;
  requested_by:       string;
  change_type:        string;
  target_system:      string;
  risk_level:         string;
  status:             string;
  approvals_required: number;
  approvals_received: { approver: string; timestamp: string; note: string }[];
  rejected_by:        string;
  rejection_reason:   string;
  execution_log:      string;
  created_at:         string;
};

type Credential = {
  id:               string;
  name:             string;
  description:      string;
  secret_path:      string;
  secret_type:      string;
  owner:            string;
  requires_approval: boolean;
  use_count:        number;
  last_used_at:     string | null;
  is_active:        boolean;
  rotation_due:     string | null;
};

type Stats = {
  total_requests:    number;
  allowed:           number;
  blocked:           number;
  pending_approval:  number;
  completed:         number;
  channel_breakdown: Record<string, number>;
  production_gates:  number;
  gates_pending:     number;
  gates_approved:    number;
  gates_completed:   number;
  credential_entries: number;
  credentials_active: number;
};

// ─── helpers ─────────────────────────────────────────────────────────────────

const CHANNEL_META: Record<string, { icon: React.ElementType; color: string; bg: string; label: string }> = {
  shell:      { icon: Terminal, color: 'text-cyan-400',   bg: 'bg-cyan-900/30 border-cyan-800',   label: 'Shell Broker' },
  browser:    { icon: Globe,    color: 'text-blue-400',   bg: 'bg-blue-900/30 border-blue-800',   label: 'Browser Sandbox' },
  credential: { icon: Key,      color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-800', label: 'Credential Broker' },
  production: { icon: Factory,  color: 'text-orange-400', bg: 'bg-orange-900/30 border-orange-800', label: 'Production Gate' },
};

const STATUS_META: Record<string, { color: string; icon: React.ElementType }> = {
  pending_approval: { color: 'text-yellow-400', icon: Clock },
  approved:         { color: 'text-blue-400',   icon: CheckCircle },
  completed:        { color: 'text-green-400',  icon: CheckCircle },
  blocked:          { color: 'text-red-400',    icon: XCircle },
  running:          { color: 'text-cyan-400',   icon: RefreshCw },
  failed:           { color: 'text-red-400',    icon: XCircle },
  rejected:         { color: 'text-red-400',    icon: XCircle },
  rolled_back:      { color: 'text-orange-400', icon: RefreshCw },
};

const RISK_COLOR: Record<string, string> = {
  low:      'text-green-400 bg-green-900/20',
  medium:   'text-yellow-400 bg-yellow-900/20',
  high:     'text-orange-400 bg-orange-900/20',
  critical: 'text-red-400 bg-red-900/20',
};

// ─── exec request row ────────────────────────────────────────────────────────

function ExecRow({ req, onAction }: { req: ExecReq; onAction: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [acting,   setActing]   = useState(false);
  const meta    = CHANNEL_META[req.channel]  ?? CHANNEL_META.shell;
  const sMeta   = STATUS_META[req.status]    ?? STATUS_META.blocked;
  const Icon    = meta.icon;
  const SIcon   = sMeta.icon;

  const doApprove = async () => {
    setActing(true);
    try {
      await approveExecRequest(req.id, { approved_by: 'platform_admin' });
      onAction();
    } finally { setActing(false); }
  };
  const doReject = async () => {
    setActing(true);
    try {
      await rejectExecRequest(req.id, {});
      onAction();
    } finally { setActing(false); }
  };
  const doExecute = async () => {
    setActing(true);
    try {
      await executeExecRequest(req.id);
      onAction();
    } finally { setActing(false); }
  };

  return (
    <>
      <tr
        className="border-b border-gray-800 hover:bg-gray-800/30 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-4 py-3">
          <span className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-lg border w-fit ${meta.bg}`}>
            <Icon className={`w-3 h-3 ${meta.color}`} />{meta.label}
          </span>
        </td>
        <td className="px-4 py-3 text-xs text-gray-300 max-w-xs">
          <p className="truncate font-mono">{req.command}</p>
          <p className="text-gray-600 mt-0.5">{req.environment}</p>
        </td>
        <td className="px-4 py-3 text-xs text-gray-400">{req.requested_by}</td>
        <td className="px-4 py-3">
          <span className={`text-xs px-2 py-0.5 rounded capitalize ${RISK_COLOR[req.risk_level] ?? ''}`}>
            {req.risk_level}
          </span>
        </td>
        <td className="px-4 py-3">
          <span className={`flex items-center gap-1.5 text-xs ${sMeta.color}`}>
            <SIcon className="w-3 h-3" /> {req.status.replace('_', ' ')}
          </span>
        </td>
        <td className="px-4 py-3">
          <div className="flex gap-2" onClick={e => e.stopPropagation()}>
            {req.status === 'pending_approval' && (
              <>
                <button
                  onClick={doApprove} disabled={acting}
                  className="flex items-center gap-1 text-xs text-green-400 hover:text-green-300 disabled:opacity-50"
                >
                  <ThumbsUp className="w-3 h-3" /> Approve
                </button>
                <button
                  onClick={doReject} disabled={acting}
                  className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50"
                >
                  <ThumbsDown className="w-3 h-3" /> Reject
                </button>
              </>
            )}
            {req.status === 'approved' && (
              <button
                onClick={doExecute} disabled={acting}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 disabled:opacity-50"
              >
                <Play className="w-3 h-3" /> Execute
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-gray-800 bg-gray-950">
          <td colSpan={6} className="px-6 py-4">
            <div className="grid grid-cols-2 gap-6">
              <div className="space-y-2 text-xs">
                {req.justification && (
                  <div>
                    <p className="text-gray-500">Justification</p>
                    <p className="text-gray-300">{req.justification}</p>
                  </div>
                )}
                {req.policy_flags?.length > 0 && (
                  <div>
                    <p className="text-gray-500 mb-1">Policy Flags</p>
                    <div className="flex flex-wrap gap-1">
                      {req.policy_flags.map(f => (
                        <span key={f} className="px-2 py-0.5 bg-yellow-900/20 border border-yellow-800 rounded text-yellow-400">
                          {f.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <div>
                  <p className="text-gray-500">Trust Score</p>
                  <p className="text-gray-300">{req.trust_score.toFixed(0)} / 100</p>
                </div>
                {req.duration_ms > 0 && (
                  <div>
                    <p className="text-gray-500">Duration</p>
                    <p className="text-gray-300">{req.duration_ms}ms</p>
                  </div>
                )}
              </div>
              {req.stdout && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Output</p>
                  <pre className="text-xs text-green-400 bg-black rounded-lg p-3 whitespace-pre-wrap">
                    {req.stdout}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── production gate card ─────────────────────────────────────────────────────

function GateCard({ gate, onAction }: { gate: ProdGate; onAction: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [approver, setApprover] = useState('platform_admin');
  const [acting,   setActing]   = useState(false);
  const sMeta = STATUS_META[gate.status] ?? STATUS_META.blocked;
  const SIcon = sMeta.icon;
  const progress = Math.round(
    ((gate.approvals_received?.length || 0) / (gate.approvals_required || 2)) * 100
  );

  const doApprove = async () => {
    setActing(true);
    try {
      await approveProductionGate(gate.id, { approved_by: approver });
      onAction();
    } finally { setActing(false); }
  };
  const doReject = async () => {
    setActing(true);
    try {
      await rejectProductionGate(gate.id, { rejected_by: 'platform_admin', reason: 'Rejected via UI' });
      onAction();
    } finally { setActing(false); }
  };
  const doExecute = async () => {
    setActing(true);
    try {
      await executeProductionGate(gate.id);
      onAction();
    } finally { setActing(false); }
  };
  const doRollback = async () => {
    setActing(true);
    try {
      await rollbackProductionGate(gate.id);
      onAction();
    } finally { setActing(false); }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div
        className="flex items-start justify-between p-5 cursor-pointer hover:bg-gray-800/30"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-3 min-w-0">
          <Factory className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-white font-medium text-sm">{gate.title}</h3>
              <span className={`text-xs px-1.5 py-0.5 rounded capitalize ${RISK_COLOR[gate.risk_level] ?? ''}`}>
                {gate.risk_level}
              </span>
              <span className={`flex items-center gap-1 text-xs ${sMeta.color}`}>
                <SIcon className="w-3 h-3" /> {gate.status.replace(/_/g, ' ')}
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              {gate.change_type} · {gate.target_system} · by {gate.requested_by}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 flex-shrink-0 ml-4">
          {/* Approval progress */}
          <div className="text-center">
            <p className="text-xs text-gray-500 mb-1">Approvals</p>
            <div className="flex items-center gap-2">
              <div className="w-16 bg-gray-800 rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full bg-orange-500"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <span className="text-xs text-gray-400">
                {gate.approvals_received?.length || 0}/{gate.approvals_required}
              </span>
            </div>
          </div>
          {expanded ? <ChevronDown className="w-4 h-4 text-gray-600" /> : <ChevronRight className="w-4 h-4 text-gray-600" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-800 p-5 space-y-4">
          {gate.description && (
            <p className="text-sm text-gray-400">{gate.description}</p>
          )}

          {/* Approvers */}
          {(gate.approvals_received?.length || 0) > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-2">Approvals Received</p>
              <div className="space-y-1">
                {gate.approvals_received.map((a, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <CheckCircle className="w-3 h-3 text-green-400" />
                    <span className="text-green-400">{a.approver}</span>
                    <span className="text-gray-600">{new Date(a.timestamp).toLocaleString()}</span>
                    {a.note && <span className="text-gray-400">"{a.note}"</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {gate.execution_log && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Execution Log</p>
              <pre className="text-xs text-gray-300 bg-black rounded-lg p-3 whitespace-pre-wrap overflow-auto max-h-40">
                {gate.execution_log}
              </pre>
            </div>
          )}

          {/* Actions */}
          {gate.status === 'pending_approval' && (
            <div className="flex items-center gap-3 flex-wrap">
              <input
                value={approver}
                onChange={e => setApprover(e.target.value)}
                placeholder="Your identity"
                className="bg-gray-800 border border-gray-700 text-white text-xs rounded-lg px-3 py-2 outline-none w-48"
              />
              <button
                onClick={doApprove} disabled={acting}
                className="flex items-center gap-1.5 text-xs px-3 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg disabled:opacity-50"
              >
                <ThumbsUp className="w-3 h-3" /> Approve
              </button>
              <button
                onClick={doReject} disabled={acting}
                className="flex items-center gap-1.5 text-xs px-3 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg disabled:opacity-50"
              >
                <ThumbsDown className="w-3 h-3" /> Reject
              </button>
            </div>
          )}
          {gate.status === 'approved' && (
            <button
              onClick={doExecute} disabled={acting}
              className="flex items-center gap-1.5 text-xs px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white rounded-lg disabled:opacity-50"
            >
              <Play className="w-3 h-3" /> Execute Production Change
            </button>
          )}
          {gate.status === 'completed' && (
            <button
              onClick={doRollback} disabled={acting}
              className="flex items-center gap-1.5 text-xs px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg disabled:opacity-50"
            >
              <RefreshCw className="w-3 h-3" /> Rollback
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ─── submit shell panel ───────────────────────────────────────────────────────

function ShellSubmitPanel({ onSubmitted }: { onSubmitted: () => void }) {
  const [form, setForm] = useState({
    command: '', environment: 'dev', requested_by: 'platform_admin', justification: '',
  });
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState<any>(null);

  const EXAMPLES = [
    'kubectl get pods -n production',
    'terraform plan -var-file=prod.tfvars',
    'aws ec2 describe-instances --region us-east-1',
    'helm upgrade --install app ./chart',
    'kubectl delete deployment nginx -n prod',
    'chmod 777 /etc/sensitive',
  ];

  const submit = async () => {
    if (!form.command) return;
    setLoading(true);
    try {
      const res = await submitShellExec(form);
      setResult(res);
      onSubmitted();
    } finally { setLoading(false); }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
      <h3 className="text-white font-semibold text-sm flex items-center gap-2">
        <Terminal className="w-4 h-4 text-cyan-400" /> Submit Shell Command
      </h3>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="text-xs text-gray-500 mb-1 block">Command</label>
          <input
            value={form.command}
            onChange={e => setForm(f => ({ ...f, command: e.target.value }))}
            placeholder="e.g. kubectl get pods -n production"
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm font-mono rounded-lg px-3 py-2 outline-none"
          />
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Environment</label>
          <select
            value={form.environment}
            onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          >
            {['dev', 'staging', 'prod', 'production'].map(e => <option key={e} value={e}>{e}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-500 mb-1 block">Requested By</label>
          <input
            value={form.requested_by}
            onChange={e => setForm(f => ({ ...f, requested_by: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
        <div className="col-span-2">
          <label className="text-xs text-gray-500 mb-1 block">Justification</label>
          <input
            value={form.justification}
            onChange={e => setForm(f => ({ ...f, justification: e.target.value }))}
            placeholder="Why is this command needed?"
            className="w-full bg-gray-800 border border-gray-700 text-white text-sm rounded-lg px-3 py-2 outline-none"
          />
        </div>
      </div>
      <div>
        <p className="text-xs text-gray-600 mb-2">Try these examples:</p>
        <div className="flex flex-wrap gap-2">
          {EXAMPLES.map(ex => (
            <button key={ex}
              onClick={() => setForm(f => ({ ...f, command: ex }))}
              className="text-xs px-2 py-1 bg-gray-800 rounded text-gray-500 hover:text-white font-mono"
            >{ex}</button>
          ))}
        </div>
      </div>
      <button
        onClick={submit} disabled={loading || !form.command}
        className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg disabled:opacity-50 flex items-center justify-center gap-2"
      >
        {loading ? <><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Evaluating…</> : <><Shield className="w-3.5 h-3.5" /> Submit to Policy Gate</>}
      </button>
      {result && (
        <div className={`p-3 rounded-lg border text-xs ${
          result.policy_decision === 'allowed'            ? 'bg-green-900/20 border-green-800 text-green-300' :
          result.policy_decision === 'requires_approval'  ? 'bg-yellow-900/20 border-yellow-800 text-yellow-300' :
                                                            'bg-red-900/20 border-red-800 text-red-300'
        }`}>
          <p className="font-semibold">Decision: {result.policy_decision?.replace('_', ' ').toUpperCase()}</p>
          <p className="mt-1">Risk: {result.risk_level} · Trust: {result.trust_score?.toFixed(0)}</p>
          {result.policy_flags?.length > 0 && (
            <p className="mt-1">Flags: {result.policy_flags.join(', ')}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

const TABS = ['Requests', 'Production Gates', 'Credentials', 'Submit'] as const;
type Tab = typeof TABS[number];

export default function ExecChannelsPage() {
  const [tab,         setTab]         = useState<Tab>('Requests');
  const [requests,    setRequests]    = useState<ExecReq[]>([]);
  const [gates,       setGates]       = useState<ProdGate[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [stats,       setStats]       = useState<Stats | null>(null);
  const [total,       setTotal]       = useState(0);
  const [loading,     setLoading]     = useState(true);
  const [channelFilter, setChannelFilter] = useState('all');
  const [statusFilter,  setStatusFilter]  = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = { limit: '50' };
      if (channelFilter !== 'all') params.channel = channelFilter;
      if (statusFilter  !== 'all') params.status  = statusFilter;
      const [reqData, gatesData, credsData, statsData] = await Promise.all([
        getExecRequests(params),
        getProductionGates(),
        getCredentials(),
        getExecStats(),
      ]);
      setRequests((reqData as any).requests || []);
      setTotal((reqData as any).total || 0);
      setGates(gatesData as ProdGate[]);
      setCredentials(credsData as Credential[]);
      setStats(statsData as Stats);
    } finally { setLoading(false); }
  }, [channelFilter, statusFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Shield className="text-cyan-400" /> Governed Execution Channels
          </h1>
          <p className="text-gray-400 mt-1 text-sm">
            Policy-gated shell, browser, credential, and production execution with full audit trail.
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 hover:text-white">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Total',     value: stats.total_requests,   color: 'text-white' },
            { label: 'Allowed',   value: stats.allowed,          color: 'text-green-400' },
            { label: 'Blocked',   value: stats.blocked,          color: stats.blocked > 0 ? 'text-red-400' : 'text-gray-600' },
            { label: 'Pending',   value: stats.pending_approval, color: stats.pending_approval > 0 ? 'text-yellow-400' : 'text-gray-600' },
            { label: 'Prod Gates', value: stats.production_gates, color: 'text-orange-400' },
            { label: 'Credentials', value: stats.credentials_active, color: 'text-yellow-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3">
              <p className="text-xs text-gray-500">{s.label}</p>
              <p className={`text-2xl font-bold mt-0.5 ${s.color}`}>{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Channel breakdown */}
      {stats?.channel_breakdown && (
        <div className="grid grid-cols-4 gap-3">
          {Object.entries(stats.channel_breakdown).map(([ch, cnt]) => {
            const meta = CHANNEL_META[ch] ?? CHANNEL_META.shell;
            const Icon = meta.icon;
            return (
              <div key={ch} className={`rounded-xl border p-4 flex items-center gap-3 ${meta.bg}`}>
                <Icon className={`w-6 h-6 ${meta.color} flex-shrink-0`} />
                <div>
                  <p className={`text-xl font-bold ${meta.color}`}>{cnt}</p>
                  <p className="text-xs text-gray-500">{meta.label}</p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Security notice */}
      <div className="bg-orange-900/20 border border-orange-800 rounded-xl px-5 py-3 flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-orange-300 text-sm font-medium">Governed Execution — All commands are policy-evaluated before execution</p>
          <p className="text-orange-600 text-xs mt-0.5">
            Shell commands run in an isolated sandbox. Credentials are injected directly — never returned via API.
            Production changes require dual approval and generate a full audit trail.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-lg text-sm transition-colors ${tab === t ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
          >{t}</button>
        ))}
      </div>

      {/* ── Requests ── */}
      {tab === 'Requests' && (
        <>
          <div className="flex flex-wrap gap-3">
            <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
              {['all', 'shell', 'browser', 'credential', 'production'].map(c => (
                <button key={c} onClick={() => setChannelFilter(c)}
                  className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${channelFilter === c ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
                >{c}</button>
              ))}
            </div>
            <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
              {['all', 'pending_approval', 'approved', 'completed', 'blocked'].map(s => (
                <button key={s} onClick={() => setStatusFilter(s)}
                  className={`text-xs px-3 py-1.5 rounded-lg capitalize transition-colors ${statusFilter === s ? 'bg-gray-700 text-white' : 'text-gray-400 hover:text-white'}`}
                >{s.replace('_', ' ')}</button>
              ))}
            </div>
            <span className="text-xs text-gray-500 self-center">{total} requests</span>
          </div>

          {loading ? (
            <div className="flex justify-center py-12"><RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" /></div>
          ) : (
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500 text-xs">
                    <th className="px-4 py-3 text-left">Channel</th>
                    <th className="px-4 py-3 text-left">Command</th>
                    <th className="px-4 py-3 text-left">Requested By</th>
                    <th className="px-4 py-3 text-left">Risk</th>
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {requests.map(r => <ExecRow key={r.id} req={r} onAction={load} />)}
                </tbody>
              </table>
              {requests.length === 0 && (
                <p className="text-center py-12 text-gray-500 text-sm">
                  No execution requests yet. Use the Submit tab to test the policy gate.
                </p>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Production Gates ── */}
      {tab === 'Production Gates' && (
        <div className="space-y-4">
          {loading ? (
            <div className="flex justify-center py-12"><RefreshCw className="w-7 h-7 text-cyan-400 animate-spin" /></div>
          ) : gates.length === 0 ? (
            <p className="text-center py-12 text-gray-500 text-sm">
              No production gates created yet. Use the Submit tab to create one.
            </p>
          ) : (
            gates.map(g => <GateCard key={g.id} gate={g} onAction={load} />)
          )}
        </div>
      )}

      {/* ── Credentials ── */}
      {tab === 'Credentials' && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
            <h3 className="text-white font-semibold text-sm flex items-center gap-2">
              <Key className="w-4 h-4 text-yellow-400" /> Credential Broker Registry
            </h3>
            <p className="text-xs text-gray-500">
              Secret values are never stored here — only metadata. Secrets are fetched from the vault at injection time.
            </p>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 text-xs">
                <th className="px-5 py-3 text-left">Name</th>
                <th className="px-5 py-3 text-left">Type</th>
                <th className="px-5 py-3 text-left">Secret Path</th>
                <th className="px-5 py-3 text-left">Owner</th>
                <th className="px-5 py-3 text-left">Uses</th>
                <th className="px-5 py-3 text-left">Approval</th>
                <th className="px-5 py-3 text-left">Active</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {credentials.map(c => (
                <tr key={c.id} className="hover:bg-gray-800/30">
                  <td className="px-5 py-3">
                    <p className="text-white text-xs font-medium">{c.name}</p>
                    <p className="text-gray-600 text-xs">{c.description}</p>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs capitalize">{c.secret_type}</td>
                  <td className="px-5 py-3 text-gray-400 text-xs font-mono">{c.secret_path}</td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{c.owner}</td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{c.use_count}</td>
                  <td className="px-5 py-3">
                    {c.requires_approval
                      ? <span className="text-xs text-yellow-400 flex items-center gap-1"><Lock className="w-3 h-3" /> Required</span>
                      : <span className="text-xs text-gray-500">Not required</span>
                    }
                  </td>
                  <td className="px-5 py-3">
                    {c.is_active
                      ? <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                      : <XCircle    className="w-3.5 h-3.5 text-red-400" />
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {credentials.length === 0 && (
            <p className="px-5 py-8 text-gray-500 text-sm text-center">
              No credentials registered in the broker.
            </p>
          )}
        </div>
      )}

      {/* ── Submit ── */}
      {tab === 'Submit' && (
        <div className="max-w-2xl">
          <ShellSubmitPanel onSubmitted={load} />
        </div>
      )}
    </div>
  );
}

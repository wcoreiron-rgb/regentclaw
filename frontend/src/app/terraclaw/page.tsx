'use client';
import { useEffect, useState, useCallback } from 'react';
import {
  Container, RefreshCw, Plug, ChevronDown, ChevronRight,
  ShieldCheck, ShieldAlert, ShieldX, AlertTriangle,
  Code2, Wand2, FileSearch, ClipboardList, BarChart3,
  Copy, CheckCheck, ExternalLink, Hammer, Terminal, Settings2, ChevronUp,
} from 'lucide-react';
import { apiFetch } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type Decision = 'APPROVE' | 'WARN' | 'BLOCK';

interface ReviewFinding {
  id: string;
  name: string;
  category: string;
  severity: string;
  risk_delta: number;
  secure_score_delta: number;
  frameworks: string[];
  remediation: string;
  line_hint?: number;
}

interface ReviewResult {
  review_id: string;
  decision: Decision;
  risk_score: number;
  secure_score: number;
  finding_count: number;
  findings: ReviewFinding[];
  frameworks_impacted: Record<string, number>;
  recommended_actions: string[];
  execution_time_ms: number;
}

interface GenerateResult {
  generate_id: string;
  decision: Decision;
  risk_score: number;
  secure_score: number;
  terraform: string;
  template_used: string;
  security_review: { finding_count: number; findings: ReviewFinding[] };
  notes: string[];
  execution_time_ms: number;
}

interface PlanChange {
  action: string;
  resource_type: string;
  resource_name: string;
  attribute_changes: Record<string, unknown>;
}

interface PlanResult {
  plan_id: string;
  decision: Decision;
  risk_score: number;
  summary: { creates: number; updates: number; deletes: number; replacements: number; total_changes: number };
  risky_changes: Array<{ resource: string; action: string; severity: string; reason: string; risk_delta: number; new_value?: string }>;
  recommended_actions: string[];
  execution_time_ms: number;
}

interface BuildResult {
  build_id: string;
  decision: Decision;
  risk_score: number;
  secure_score: number;
  intent: {
    detected_cloud: string;
    detected_resource: string;
    detected_environment: string;
    detected_region: string;
    module_generated: string;
  };
  arc_scan: {
    injection_risk: boolean;
    risk_score: number;
    vectors_flagged: string[];
    sensitive_patterns: unknown[];
    risk_level: string;
    agt_used: boolean;
  };
  module: {
    files: Record<string, string>;
    file_count: number;
    deploy_target: Record<string, string>;
  };
  security_review: {
    findings: ReviewFinding[];
    finding_count: number;
    always_included_security: string[];
  };
  plan: {
    what: string;
    resources: string[];
    security_modules: string[];
    deploy_steps: string[];
  };
  terraform_mcp: {
    available: boolean;
    provider_hints: string;
    configure_via: string;
  };
  policy_decision: {
    outcome: string;
    policy_name: string;
  };
  execution_time_ms: number;
}

// ─── Style helpers ────────────────────────────────────────────────────────────

const SEV: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  CRITICAL: { color: 'text-red-400',    bg: 'bg-red-900/20',    border: 'border-red-800',    dot: 'bg-red-500'    },
  HIGH:     { color: 'text-orange-400', bg: 'bg-orange-900/20', border: 'border-orange-800', dot: 'bg-orange-500' },
  MEDIUM:   { color: 'text-yellow-400', bg: 'bg-yellow-900/20', border: 'border-yellow-800', dot: 'bg-yellow-500' },
  LOW:      { color: 'text-blue-400',   bg: 'bg-blue-900/20',   border: 'border-blue-800',   dot: 'bg-blue-500'   },
};
const sev = (s: string) => SEV[s?.toUpperCase()] ?? SEV.LOW;

const DECISION_STYLE: Record<Decision, { color: string; bg: string; border: string; icon: React.ElementType; label: string }> = {
  APPROVE: { color: 'text-green-300',  bg: 'bg-green-900/30',  border: 'border-green-700', icon: ShieldCheck, label: 'APPROVE — Safe to apply' },
  WARN:    { color: 'text-yellow-300', bg: 'bg-yellow-900/30', border: 'border-yellow-700',icon: ShieldAlert, label: 'WARN — Review findings before applying' },
  BLOCK:   { color: 'text-red-300',    bg: 'bg-red-900/30',    border: 'border-red-700',   icon: ShieldX,     label: 'BLOCK — Do not apply until risks are resolved' },
};

function DecisionBanner({ decision, risk_score, secure_score }: { decision: Decision; risk_score: number; secure_score: number }) {
  const ds = DECISION_STYLE[decision];
  const Icon = ds.icon;
  return (
    <div className={`flex items-center gap-4 p-4 rounded-lg border ${ds.bg} ${ds.border}`}>
      <Icon className={`w-8 h-8 flex-shrink-0 ${ds.color}`} />
      <div className="flex-1">
        <p className={`font-bold text-lg ${ds.color}`}>{ds.label}</p>
        <p className="text-sm mt-0.5" style={{ color: 'var(--rc-text-2)' }}>
          Risk Score: <span className={ds.color}>{risk_score}/100</span>
          {' · '}
          Secure Score: <span className={`${secure_score >= 80 ? 'text-green-400' : secure_score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>{secure_score}/100</span>
        </p>
      </div>
      <div className="text-right hidden sm:block">
        <div className={`text-3xl font-bold ${ds.color}`}>{risk_score}</div>
        <div className="text-xs" style={{ color: 'var(--rc-text-3)' }}>risk score</div>
      </div>
    </div>
  );
}

function FindingCard({ f, expanded, onToggle }: { f: ReviewFinding; expanded: boolean; onToggle: () => void }) {
  const s = sev(f.severity);
  return (
    <div className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
      >
        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
        <span className="flex-1 text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.name}</span>
        <span className={`text-xs font-mono px-2 py-0.5 rounded ${s.bg} ${s.color} border ${s.border}`}>{f.id}</span>
        <span className={`text-xs font-bold ${s.color}`}>{f.severity}</span>
        {f.line_hint && (
          <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>L{f.line_hint}</span>
        )}
        {expanded ? <ChevronDown className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                  : <ChevronRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
      </button>
      {expanded && (
        <div className="px-4 pb-4 space-y-2 border-t border-white/10">
          <p className="text-sm pt-3" style={{ color: 'var(--rc-text-2)' }}>
            <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Remediation: </span>
            {f.remediation}
          </p>
          <div className="flex flex-wrap gap-1.5 pt-1">
            {f.frameworks.map(fw => (
              <span key={fw} className="text-xs px-2 py-0.5 rounded bg-regent-900/40 border border-regent-800 text-regent-300">{fw}</span>
            ))}
          </div>
          <div className="flex gap-4 text-xs pt-1" style={{ color: 'var(--rc-text-3)' }}>
            <span>Risk delta: +{f.risk_delta}</span>
            <span>Secure score: {f.secure_score_delta}</span>
            <span>Category: {f.category}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="flex items-center gap-1.5 text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors" style={{ color: 'var(--rc-text-2)' }}>
      {copied ? <CheckCheck className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

// ─── Tab: Review ─────────────────────────────────────────────────────────────

function ReviewTab() {
  const [hcl, setHcl] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReviewResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const handleReview = async () => {
    if (hcl.trim().length < 10) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiFetch<ReviewResult>('/terraclaw/review', {
        method: 'POST',
        body: JSON.stringify({ hcl, context }),
      });
      setResult(res);
    } catch (e: any) {
      setError(e?.message ?? 'Review failed');
    } finally {
      setLoading(false);
    }
  };

  const EXAMPLE_HCL = `resource "azurerm_mssql_server" "prod" {
  name                          = "prod-sql"
  resource_group_name           = "prod-rg"
  location                      = "eastus"
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "Passw0rd123!"
  public_network_access_enabled = true
}`;

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Terraform HCL</label>
          <button
            onClick={() => setHcl(EXAMPLE_HCL)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors"
            style={{ color: 'var(--rc-text-3)' }}
          >
            Load example
          </button>
        </div>
        <textarea
          value={hcl}
          onChange={e => setHcl(e.target.value)}
          placeholder="Paste Terraform HCL here (.tf file content)..."
          rows={12}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm font-mono px-3 py-2 focus:outline-none focus:border-regent-500 resize-y"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>
      <div>
        <label className="text-sm font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Context (optional)</label>
        <input
          value={context}
          onChange={e => setContext(e.target.value)}
          placeholder="e.g. Production Azure SQL deployment, PR #142"
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>
      <button
        onClick={handleReview}
        disabled={loading || hcl.trim().length < 10}
        className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
        {loading ? 'Reviewing…' : 'Run Security Review'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={result.secure_score} />

          {result.findings.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Findings ({result.finding_count})
              </h3>
              {result.findings.map(f => (
                <FindingCard
                  key={f.id}
                  f={f}
                  expanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          )}

          {Object.keys(result.frameworks_impacted).length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>Frameworks Impacted</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(result.frameworks_impacted).map(([fw, count]) => (
                  <span key={fw} className="text-xs px-2 py-1 rounded bg-regent-900/40 border border-regent-800 text-regent-300">
                    {fw} <span className="opacity-60">({count})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.findings.length === 0 && (
            <div className="p-4 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              No security issues detected. Review result: {result.decision}.
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Reviewed in {result.execution_time_ms}ms · ID: {result.review_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Tab: Generate ────────────────────────────────────────────────────────────

function GenerateTab() {
  const [description, setDescription] = useState('');
  const [cloud, setCloud] = useState<'azure' | 'aws' | 'gcp'>('azure');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<GenerateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const handleGenerate = async () => {
    if (description.trim().length < 5) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await apiFetch<GenerateResult>('/terraclaw/generate', {
        method: 'POST',
        body: JSON.stringify({ description, cloud }),
      });
      setResult(res);
    } catch (e: any) {
      setError(e?.message ?? 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  const EXAMPLES = [
    'Secure Azure SQL Server with Private Endpoint and Defender',
    'Azure Storage Account with encryption and no public access',
    'AWS RDS PostgreSQL with encryption and private subnets',
    'AWS EC2 instance with SSM access (no SSH keys)',
    'Private AKS cluster with Defender for Containers',
  ];

  return (
    <div className="space-y-4">
      <div>
        <label className="text-sm font-medium mb-2 block" style={{ color: 'var(--rc-text-1)' }}>Describe what you want to deploy</label>
        <textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="e.g. Deploy a secure Azure SQL Server with Private Endpoint and Entra ID admin login"
          rows={3}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500 resize-none"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>

      <div className="flex flex-wrap gap-2">
        {EXAMPLES.map(ex => (
          <button
            key={ex}
            onClick={() => setDescription(ex)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors text-left"
            style={{ color: 'var(--rc-text-3)' }}
          >
            {ex}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <label className="text-sm font-medium" style={{ color: 'var(--rc-text-2)' }}>Cloud:</label>
        {(['azure', 'aws', 'gcp'] as const).map(c => (
          <button
            key={c}
            onClick={() => setCloud(c)}
            className={`text-sm px-3 py-1 rounded border transition-colors ${
              cloud === c
                ? 'border-regent-500 bg-regent-900/40 text-regent-300'
                : 'border-white/10 hover:bg-white/10'
            }`}
            style={cloud !== c ? { color: 'var(--rc-text-2)' } : {}}
          >
            {c.toUpperCase()}
          </button>
        ))}
      </div>

      <button
        onClick={handleGenerate}
        disabled={loading || description.trim().length < 5}
        className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
        {loading ? 'Generating…' : 'Generate Secure Terraform'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={result.secure_score} />

          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Generated Terraform
                <span className="ml-2 text-xs font-normal" style={{ color: 'var(--rc-text-3)' }}>template: {result.template_used}</span>
              </h3>
              <CopyButton text={result.terraform} />
            </div>
            <pre className="rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] p-4 text-xs font-mono overflow-auto max-h-96 leading-relaxed" style={{ color: 'var(--rc-text-1)' }}>
              {result.terraform}
            </pre>
          </div>

          {result.security_review.finding_count === 0 ? (
            <div className="p-3 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              Security review passed — generated code uses secure-by-default settings.
            </div>
          ) : (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Security Review ({result.security_review.finding_count} findings)
              </h3>
              {result.security_review.findings.map(f => (
                <FindingCard
                  key={f.id}
                  f={f}
                  expanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          )}

          {result.notes.length > 0 && (
            <div className="p-3 rounded-lg bg-blue-900/20 border border-blue-800 space-y-1">
              {result.notes.map((n, i) => (
                <p key={i} className="text-sm text-blue-300">• {n}</p>
              ))}
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Generated in {result.execution_time_ms}ms · ID: {result.generate_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Tab: Plan Analysis ───────────────────────────────────────────────────────

const PLAN_EXAMPLE_JSON = JSON.stringify([
  {
    action: 'update',
    resource_type: 'azurerm_mssql_server',
    resource_name: 'prod-sql',
    attribute_changes: { public_network_access_enabled: true },
  },
  {
    action: 'create',
    resource_type: 'azurerm_private_endpoint',
    resource_name: 'sql-pe',
    attribute_changes: {},
  },
  {
    action: 'delete',
    resource_type: 'azurerm_network_security_rule',
    resource_name: 'allow-internal-only',
    attribute_changes: {},
  },
], null, 2);

function PlanTab() {
  const [planJson, setPlanJson] = useState('');
  const [context, setContext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setPlanResult] = useState<PlanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    setParseError(null);
    setError(null);
    let changes: PlanChange[];
    try {
      changes = JSON.parse(planJson);
      if (!Array.isArray(changes)) throw new Error('Expected a JSON array of changes');
    } catch (e: any) {
      setParseError(`JSON parse error: ${e.message}`);
      return;
    }
    setLoading(true);
    setPlanResult(null);
    try {
      const res = await apiFetch<PlanResult>('/terraclaw/plan', {
        method: 'POST',
        body: JSON.stringify({ changes, context }),
      });
      setPlanResult(res);
    } catch (e: any) {
      setError(e?.message ?? 'Plan analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const SMAP: Record<string, string> = {
    CRITICAL: 'text-red-400', HIGH: 'text-orange-400', MEDIUM: 'text-yellow-400', LOW: 'text-blue-400',
  };

  return (
    <div className="space-y-4">
      <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
        Paste a JSON array of planned changes — each with <code className="text-xs bg-white/10 px-1 rounded">action</code>, <code className="text-xs bg-white/10 px-1 rounded">resource_type</code>, <code className="text-xs bg-white/10 px-1 rounded">resource_name</code>, and <code className="text-xs bg-white/10 px-1 rounded">attribute_changes</code>.
      </p>

      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>Plan Changes (JSON)</label>
          <button
            onClick={() => setPlanJson(PLAN_EXAMPLE_JSON)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors"
            style={{ color: 'var(--rc-text-3)' }}
          >
            Load example
          </button>
        </div>
        <textarea
          value={planJson}
          onChange={e => { setPlanJson(e.target.value); setParseError(null); }}
          placeholder='[{"action":"update","resource_type":"azurerm_mssql_server","resource_name":"prod-sql","attribute_changes":{"public_network_access_enabled":true}}]'
          rows={10}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm font-mono px-3 py-2 focus:outline-none focus:border-regent-500 resize-y"
          style={{ color: 'var(--rc-text-1)' }}
        />
        {parseError && <p className="text-xs text-red-400 mt-1">{parseError}</p>}
      </div>

      <div>
        <label className="text-sm font-medium mb-1 block" style={{ color: 'var(--rc-text-2)' }}>Context (optional)</label>
        <input
          value={context}
          onChange={e => setContext(e.target.value)}
          placeholder="e.g. Pre-prod Terraform apply — sprint 7 deployment"
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>

      <button
        onClick={handleAnalyze}
        disabled={loading || planJson.trim().length < 5}
        className="px-4 py-2 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
        {loading ? 'Analyzing…' : 'Analyze Plan'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {result && (
        <div className="space-y-4 mt-2">
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={100 - result.risk_score} />

          {/* Summary chips */}
          <div className="flex flex-wrap gap-2">
            {[
              { label: 'Creates', val: result.summary.creates, color: 'text-green-400' },
              { label: 'Updates', val: result.summary.updates, color: 'text-blue-400' },
              { label: 'Deletes', val: result.summary.deletes, color: 'text-red-400' },
              { label: 'Replacements', val: result.summary.replacements, color: 'text-orange-400' },
            ].map(({ label, val, color }) => (
              <div key={label} className="px-3 py-1.5 rounded border border-white/10 bg-white/5">
                <span className={`text-base font-bold ${color}`}>{val}</span>
                <span className="text-xs ml-1" style={{ color: 'var(--rc-text-3)' }}>{label}</span>
              </div>
            ))}
          </div>

          {result.risky_changes.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--rc-text-1)' }}>
                Risky Changes ({result.risky_changes.length})
              </h3>
              <div className="space-y-2">
                {result.risky_changes.map((c, i) => {
                  const color = SMAP[c.severity] ?? 'text-gray-400';
                  return (
                    <div key={i} className="p-3 rounded-lg border border-white/10 bg-white/5 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <code className="text-xs font-mono" style={{ color: 'var(--rc-text-1)' }}>{c.resource}</code>
                        <span className={`text-xs font-bold flex-shrink-0 ${color}`}>{c.severity}</span>
                      </div>
                      <p className="text-xs" style={{ color: 'var(--rc-text-2)' }}>
                        <span className="font-mono bg-white/10 px-1 rounded">{c.action}</span>
                        {c.new_value && <span className="ml-2 text-orange-300">→ {c.new_value}</span>}
                      </p>
                      <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{c.reason}</p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {result.risky_changes.length === 0 && (
            <div className="p-3 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              No risky attribute changes detected. Plan looks safe to apply.
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Analyzed in {result.execution_time_ms}ms · ID: {result.plan_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Tab: Findings ────────────────────────────────────────────────────────────

function FindingsTab() {
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats]       = useState<any>(null);
  const [providers, setProviders] = useState<any[]>([]);
  const [loading, setLoading]   = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg]   = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, f, p] = await Promise.all([
        apiFetch<any>('/terraclaw/stats'),
        apiFetch<any[]>('/terraclaw/findings'),
        apiFetch<any[]>('/terraclaw/providers'),
      ]);
      setStats(s); setFindings(f); setProviders(p);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleScan = async () => {
    setScanning(true); setScanMsg(null);
    try {
      const res = await apiFetch<any>('/terraclaw/scan', { method: 'POST' });
      await load();
      setScanMsg({ type: 'success', text: `Scan complete — ${res.findings_created ?? 0} new, ${res.findings_updated ?? 0} updated.` });
    } catch (e: any) {
      setScanMsg({ type: 'error', text: `Scan failed: ${e?.message ?? 'Unknown error'}` });
    } finally {
      setScanning(false);
      setTimeout(() => setScanMsg(null), 8000);
    }
  };

  const shown = filterSev === 'all' ? findings : findings.filter(f => f.severity?.toUpperCase() === filterSev);
  const configured = providers.filter(p => p.configured).length;

  if (loading) {
    return <div className="text-sm py-8 text-center" style={{ color: 'var(--rc-text-3)' }}>Loading findings…</div>;
  }

  return (
    <div className="space-y-4">
      {/* KPI row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            { label: 'Total', val: stats.total, c: 'text-green-400 bg-green-900/20 border-green-800' },
            { label: 'Critical', val: stats.critical, c: 'text-red-400 bg-red-900/20 border-red-800' },
            { label: 'High', val: stats.high, c: 'text-orange-400 bg-orange-900/20 border-orange-800' },
            { label: 'Medium', val: stats.medium, c: 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
            { label: 'Secure Score', val: stats.secure_score ?? '—', c: (stats.secure_score ?? 0) >= 80 ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-yellow-400 bg-yellow-900/20 border-yellow-800' },
            { label: 'Connectors', val: `${configured}/${providers.length}`, c: configured > 0 ? 'text-green-400 bg-green-900/20 border-green-800' : 'text-gray-400 bg-gray-900/20 border-gray-700' },
          ].map(({ label, val, c }) => (
            <div key={label} className={`rounded-lg border px-3 py-2.5 text-center ${c}`}>
              <div className="text-xl font-bold">{val}</div>
              <div className="text-xs opacity-70">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3 flex-wrap">
        <button
          onClick={handleScan}
          disabled={scanning}
          className="px-3 py-1.5 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          {scanning ? 'Scanning…' : 'Run Scan'}
        </button>
        {(['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
          <button
            key={s}
            onClick={() => setFilterSev(s)}
            className={`text-xs px-2.5 py-1 rounded border transition-colors ${filterSev === s ? 'border-regent-500 bg-regent-900/40 text-regent-300' : 'border-white/10 hover:bg-white/10'}`}
            style={filterSev !== s ? { color: 'var(--rc-text-2)' } : {}}
          >
            {s === 'all' ? 'All' : s}
          </button>
        ))}
      </div>

      {scanMsg && (
        <div className={`p-3 rounded-lg border text-sm ${scanMsg.type === 'success' ? 'bg-green-900/20 border-green-800 text-green-300' : 'bg-red-900/20 border-red-800 text-red-300'}`}>
          {scanMsg.text}
        </div>
      )}

      {/* Findings list */}
      <div className="space-y-2">
        {shown.map((f: any) => {
          const s = sev(f.severity);
          const id = f.id;
          return (
            <div key={id} className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden`}>
              <button
                onClick={() => setExpanded(expanded === id ? null : id)}
                className="w-full flex items-center gap-3 p-3 text-left hover:bg-white/5 transition-colors"
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.dot}`} />
                <span className="flex-1 text-sm font-medium" style={{ color: 'var(--rc-text-1)' }}>{f.title}</span>
                <span className={`text-xs font-bold ${s.color} flex-shrink-0`}>{f.severity}</span>
                <span className="text-xs flex-shrink-0" style={{ color: 'var(--rc-text-3)' }}>{f.resource_type}</span>
                {expanded === id ? <ChevronDown className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />
                                : <ChevronRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--rc-text-3)' }} />}
              </button>
              {expanded === id && (
                <div className="px-4 pb-4 space-y-2 border-t border-white/10">
                  <p className="text-sm pt-3" style={{ color: 'var(--rc-text-2)' }}>{f.description}</p>
                  <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
                    <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Remediation: </span>
                    {f.remediation}
                  </p>
                  <div className="flex flex-wrap gap-2 text-xs" style={{ color: 'var(--rc-text-3)' }}>
                    {f.resource_name && <span>Resource: <span style={{ color: 'var(--rc-text-2)' }}>{f.resource_name}</span></span>}
                    {f.region && <span>Region: <span style={{ color: 'var(--rc-text-2)' }}>{f.region}</span></span>}
                    {f.provider && <span>Provider: <span style={{ color: 'var(--rc-text-2)' }}>{f.provider}</span></span>}
                  </div>
                  {f.frameworks && f.frameworks.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {f.frameworks.map((fw: string) => (
                        <span key={fw} className="text-xs px-2 py-0.5 rounded bg-regent-900/40 border border-regent-800 text-regent-300">{fw}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        {shown.length === 0 && (
          <p className="text-sm text-center py-8" style={{ color: 'var(--rc-text-3)' }}>
            No findings for the selected filter.
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Tab: Compliance ──────────────────────────────────────────────────────────

const FRAMEWORK_RULES: Record<string, { id: string; name: string; ruleIds: string[] }[]> = {
  'CIS Azure': [
    { id: 'CIS-AZ-3.1',  name: 'Ensure HTTPS-only traffic on Storage Accounts', ruleIds: ['TC-DATA-002'] },
    { id: 'CIS-AZ-3.7',  name: 'Ensure public blob access is disabled', ruleIds: ['TC-DATA-001'] },
    { id: 'CIS-AZ-4.1',  name: 'Ensure SQL Server disables public network access', ruleIds: ['TC-NET-004'] },
    { id: 'CIS-AZ-6.1',  name: 'Ensure RDP access is restricted from internet', ruleIds: ['TC-NET-002'] },
    { id: 'CIS-AZ-6.2',  name: 'Ensure SSH access is restricted from internet', ruleIds: ['TC-NET-001'] },
    { id: 'CIS-AZ-8.2',  name: 'Ensure AKS cluster API server is private', ruleIds: ['TC-NET-005'] },
  ],
  'CIS AWS': [
    { id: 'CIS-AWS-4.1', name: 'Ensure no security groups allow SSH from 0.0.0.0/0', ruleIds: ['TC-NET-001', 'TC-NET-003'] },
    { id: 'CIS-AWS-4.2', name: 'Ensure no security groups allow RDP from 0.0.0.0/0', ruleIds: ['TC-NET-002'] },
    { id: 'CIS-AWS-2.3', name: 'Ensure RDS instances have encryption enabled', ruleIds: ['TC-DATA-003'] },
  ],
  'NIST 800-53': [
    { id: 'NIST-AC-6',   name: 'Least Privilege', ruleIds: ['TC-IAM-001', 'TC-IAM-002'] },
    { id: 'NIST-SC-7',   name: 'Boundary Protection', ruleIds: ['TC-NET-001', 'TC-NET-002', 'TC-NET-003', 'TC-NET-004', 'TC-NET-005'] },
    { id: 'NIST-SC-8',   name: 'Transmission Confidentiality', ruleIds: ['TC-DATA-002', 'TC-DATA-004'] },
    { id: 'NIST-SC-28',  name: 'Protection of Information at Rest', ruleIds: ['TC-DATA-003', 'TC-DATA-001'] },
    { id: 'NIST-AU-2',   name: 'Event Logging', ruleIds: ['TC-MON-001', 'TC-MON-002'] },
    { id: 'NIST-IA-5',   name: 'Authenticator Management', ruleIds: ['TC-SEC-001'] },
  ],
  'SOC 2': [
    { id: 'CC6.1',  name: 'Logical and Physical Access Controls', ruleIds: ['TC-DATA-001', 'TC-DATA-003'] },
    { id: 'CC6.2',  name: 'Authenticator Management', ruleIds: ['TC-SEC-001'] },
    { id: 'CC6.3',  name: 'Least Privilege Access', ruleIds: ['TC-IAM-001', 'TC-IAM-002'] },
    { id: 'CC6.6',  name: 'Network Restriction', ruleIds: ['TC-NET-001', 'TC-NET-002', 'TC-NET-004', 'TC-NET-005'] },
    { id: 'CC6.7',  name: 'Transmission Encryption', ruleIds: ['TC-DATA-002', 'TC-DATA-004'] },
    { id: 'CC7.2',  name: 'Monitoring of System Components', ruleIds: ['TC-MON-001', 'TC-MON-002'] },
  ],
};

function ComplianceTab() {
  const [selectedFW, setSelectedFW] = useState('CIS Azure');
  const controls = FRAMEWORK_RULES[selectedFW] ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {Object.keys(FRAMEWORK_RULES).map(fw => (
          <button
            key={fw}
            onClick={() => setSelectedFW(fw)}
            className={`text-sm px-3 py-1.5 rounded border transition-colors ${
              selectedFW === fw
                ? 'border-regent-500 bg-regent-900/40 text-regent-300'
                : 'border-white/10 hover:bg-white/10'
            }`}
            style={selectedFW !== fw ? { color: 'var(--rc-text-2)' } : {}}
          >
            {fw}
          </button>
        ))}
      </div>

      <div className="rounded-lg border border-white/10 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/10" style={{ background: 'var(--rc-bg-elevated)' }}>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>Control ID</th>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>Control Name</th>
              <th className="text-left px-4 py-2.5 font-medium" style={{ color: 'var(--rc-text-2)' }}>TerraClaw Rules</th>
            </tr>
          </thead>
          <tbody>
            {controls.map((ctrl, i) => (
              <tr key={ctrl.id} className={`border-b border-white/5 ${i % 2 === 0 ? '' : 'bg-white/2'} hover:bg-white/5 transition-colors`}>
                <td className="px-4 py-3 font-mono text-xs text-regent-300">{ctrl.id}</td>
                <td className="px-4 py-3" style={{ color: 'var(--rc-text-1)' }}>{ctrl.name}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {ctrl.ruleIds.map(rid => (
                      <span key={rid} className="text-xs px-1.5 py-0.5 rounded bg-white/10 font-mono" style={{ color: 'var(--rc-text-2)' }}>{rid}</span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="p-4 rounded-lg bg-blue-900/10 border border-blue-900/40">
        <p className="text-sm" style={{ color: 'var(--rc-text-2)' }}>
          Compliance coverage is based on TerraClaw security rules mapped to framework controls.
          Run a <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Review</span> or <span className="font-semibold" style={{ color: 'var(--rc-text-1)' }}>Scan</span> to generate evidence against these controls.
          For a full evidence export, use <span className="font-semibold text-green-400">ComplianceClaw → Evidence Export</span>.
        </p>
      </div>
    </div>
  );
}

// ─── Tab: Build ──────────────────────────────────────────────────────────────

const BUILD_EXAMPLES = [
  'Deploy a secure Azure SQL Server for a production finance application',
  'Create an Azure Storage Account for storing encrypted audit logs',
  'Set up an AWS RDS PostgreSQL database for the payment service',
  'Launch a private EC2 instance for a backend API (no SSH, use SSM)',
  'Build a private AKS cluster for microservices with Defender for Containers',
];

function BuildTab() {
  const [description, setDescription] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [cloud, setCloud] = useState('');
  const [region, setRegion] = useState('');
  const [environment, setEnvironment] = useState('');
  const [prefix, setPrefix] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BuildResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeFile, setActiveFile] = useState<string>('main.tf');
  const [expanded, setExpanded] = useState<string | null>(null);

  const handleBuild = async () => {
    if (description.trim().length < 5) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const body: Record<string, unknown> = { description };
      if (cloud) body.cloud = cloud;
      if (region) body.region = region;
      if (environment) body.environment = environment;
      if (prefix) body.prefix = prefix;
      const res = await apiFetch<BuildResult>('/terraclaw/build', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      setResult(res);
      const firstFile = res.module?.files ? Object.keys(res.module.files)[0] : 'main.tf';
      setActiveFile(res.module?.files?.['main.tf'] ? 'main.tf' : firstFile);
    } catch (e: any) {
      setError(e?.message ?? 'Build failed');
    } finally {
      setLoading(false);
    }
  };

  const fileNames = result ? Object.keys(result.module.files) : [];

  return (
    <div className="space-y-5">
      {/* Intro banner */}
      <div className="p-4 rounded-lg border border-regent-800/60 bg-gradient-to-r from-regent-900/40 to-transparent">
        <p className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
          Natural-language Terraform wizard
        </p>
        <p className="text-xs mt-0.5" style={{ color: 'var(--rc-text-2)' }}>
          Describe what you want to deploy. TerraClaw generates a production-ready, security-hardened
          Terraform module — ArcClaw scans your input before generation and the output before delivery.
        </p>
      </div>

      {/* Description */}
      <div>
        <label className="text-sm font-medium mb-2 block" style={{ color: 'var(--rc-text-1)' }}>
          What do you want to deploy?
        </label>
        <textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          placeholder="e.g. I need a private Azure SQL Server for a production finance app. It should use Entra ID for auth, be private-endpoint only, and have full audit logging enabled."
          rows={4}
          className="w-full rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] text-sm px-3 py-2 focus:outline-none focus:border-regent-500 resize-none"
          style={{ color: 'var(--rc-text-1)' }}
        />
      </div>

      {/* Quick-fill examples */}
      <div className="flex flex-wrap gap-2">
        {BUILD_EXAMPLES.map(ex => (
          <button
            key={ex}
            onClick={() => setDescription(ex)}
            className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10 transition-colors text-left max-w-xs truncate"
            style={{ color: 'var(--rc-text-3)' }}
            title={ex}
          >
            {ex}
          </button>
        ))}
      </div>

      {/* Advanced overrides */}
      <div>
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10 transition-colors"
          style={{ color: 'var(--rc-text-2)' }}
        >
          <Settings2 className="w-3.5 h-3.5" />
          Override deployment target
          {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
        {showAdvanced && (
          <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div>
              <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-3)' }}>Cloud</label>
              <select
                value={cloud}
                onChange={e => setCloud(e.target.value)}
                className="w-full rounded-md border border-white/10 bg-[var(--rc-bg-elevated)] text-xs px-2 py-1.5 focus:outline-none focus:border-regent-500"
                style={{ color: 'var(--rc-text-1)' }}
              >
                <option value="">Auto-detect</option>
                <option value="azure">Azure</option>
                <option value="aws">AWS</option>
                <option value="gcp">GCP</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-3)' }}>Environment</label>
              <select
                value={environment}
                onChange={e => setEnvironment(e.target.value)}
                className="w-full rounded-md border border-white/10 bg-[var(--rc-bg-elevated)] text-xs px-2 py-1.5 focus:outline-none focus:border-regent-500"
                style={{ color: 'var(--rc-text-1)' }}
              >
                <option value="">Auto-detect</option>
                <option value="prod">Production</option>
                <option value="staging">Staging</option>
                <option value="dev">Development</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-3)' }}>Region</label>
              <input
                value={region}
                onChange={e => setRegion(e.target.value)}
                placeholder="e.g. eastus"
                className="w-full rounded-md border border-white/10 bg-[var(--rc-bg-elevated)] text-xs px-2 py-1.5 focus:outline-none focus:border-regent-500"
                style={{ color: 'var(--rc-text-1)' }}
              />
            </div>
            <div>
              <label className="text-xs font-medium mb-1 block" style={{ color: 'var(--rc-text-3)' }}>Resource prefix</label>
              <input
                value={prefix}
                onChange={e => setPrefix(e.target.value)}
                placeholder="e.g. myapp-prod"
                className="w-full rounded-md border border-white/10 bg-[var(--rc-bg-elevated)] text-xs px-2 py-1.5 focus:outline-none focus:border-regent-500"
                style={{ color: 'var(--rc-text-1)' }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Build button */}
      <button
        onClick={handleBuild}
        disabled={loading || description.trim().length < 5}
        className="px-5 py-2.5 rounded-lg bg-regent-600 hover:bg-regent-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
      >
        {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Hammer className="w-4 h-4" />}
        {loading ? 'Building module…' : 'Build Secure Terraform'}
      </button>

      {error && (
        <div className="p-3 rounded-lg bg-red-900/20 border border-red-800 text-sm text-red-300">{error}</div>
      )}

      {/* ── Results ── */}
      {result && (
        <div className="space-y-5 mt-2 pt-2 border-t border-white/10">

          {/* ArcClaw scan status */}
          <div className={`flex items-center gap-3 p-3 rounded-lg border text-sm ${
            result.arc_scan.injection_risk
              ? 'bg-yellow-900/20 border-yellow-800 text-yellow-300'
              : 'bg-green-900/20 border-green-800 text-green-300'
          }`}>
            {result.arc_scan.injection_risk
              ? <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              : <ShieldCheck className="w-4 h-4 flex-shrink-0" />}
            <div className="flex-1">
              <span className="font-medium">ArcClaw: </span>
              {result.arc_scan.injection_risk
                ? `Injection signals detected (risk ${result.arc_scan.risk_score}/100) — output generated with caution`
                : `Input safe — no injection risk (${result.arc_scan.risk_level} risk level)`}
            </div>
            {result.arc_scan.agt_used && (
              <span className="text-xs opacity-60 flex-shrink-0 px-1.5 py-0.5 rounded bg-white/10">AGT</span>
            )}
          </div>

          {/* Decision banner */}
          <DecisionBanner decision={result.decision} risk_score={result.risk_score} secure_score={result.secure_score} />

          {/* Detected intent chips */}
          <div className="p-4 rounded-lg border border-white/10 bg-white/3 space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--rc-text-3)' }}>Detected intent</h3>
            <div className="flex flex-wrap gap-2">
              {[
                { label: 'Cloud',       val: result.intent.detected_cloud.toUpperCase()       },
                { label: 'Resource',    val: result.intent.detected_resource                  },
                { label: 'Environment', val: result.intent.detected_environment.toUpperCase() },
                { label: 'Region',      val: result.intent.detected_region                    },
                { label: 'Module',      val: result.intent.module_generated                   },
              ].map(({ label, val }) => (
                <div key={label} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/10 bg-white/5">
                  <span className="text-xs" style={{ color: 'var(--rc-text-3)' }}>{label}:</span>
                  <span className="text-xs font-medium text-regent-300">{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Plain-English plan */}
          {result.plan?.what && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>What this will deploy</h3>
              <div className="p-3 rounded-lg border border-regent-800 bg-regent-900/20">
                <p className="text-sm font-medium text-regent-200">{result.plan.what}</p>
              </div>
              <div className="space-y-1.5">
                {result.plan.resources.map((r, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs" style={{ color: 'var(--rc-text-2)' }}>
                    <span className="text-regent-400 mt-0.5 flex-shrink-0">▸</span>
                    <span className="font-mono leading-relaxed">{r}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Always-included security modules */}
          {result.security_review?.always_included_security?.length > 0 && (
            <div className="p-4 rounded-lg border border-green-900/50 bg-green-900/10 space-y-2">
              <h3 className="text-sm font-semibold text-green-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 flex-shrink-0" />
                Always-included security modules
              </h3>
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                These security controls are automatically wired into every generated module.
              </p>
              <div className="flex flex-wrap gap-2 pt-1">
                {result.security_review.always_included_security.map((m, i) => (
                  <span key={i} className="text-xs px-2 py-1 rounded border border-green-900/60 bg-green-900/20 text-green-400 font-mono">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Generated Terraform files */}
          <div className="space-y-2">
            <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
              Generated Terraform module
              <span className="ml-2 text-xs font-normal" style={{ color: 'var(--rc-text-3)' }}>
                {result.module.file_count} file{result.module.file_count !== 1 ? 's' : ''}
              </span>
            </h3>
            {/* File tabs */}
            <div className="flex items-end gap-1 border-b border-white/10">
              {fileNames.map(fname => (
                <button
                  key={fname}
                  onClick={() => setActiveFile(fname)}
                  className={`flex items-center gap-1.5 px-3 py-2 text-xs font-mono border-b-2 transition-colors ${
                    activeFile === fname
                      ? 'border-regent-500 text-regent-300'
                      : 'border-transparent hover:border-white/20'
                  }`}
                  style={activeFile !== fname ? { color: 'var(--rc-text-2)' } : {}}
                >
                  <Code2 className="w-3 h-3" />
                  {fname}
                </button>
              ))}
              {result.module.files[activeFile] && (
                <div className="ml-auto pb-1">
                  <CopyButton text={result.module.files[activeFile]} />
                </div>
              )}
            </div>
            {result.module.files[activeFile] && (
              <pre className="rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] p-4 text-xs font-mono overflow-auto max-h-[520px] leading-relaxed" style={{ color: 'var(--rc-text-1)' }}>
                {result.module.files[activeFile]}
              </pre>
            )}
            {result.terraform_mcp && (
              <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
                {result.terraform_mcp.available
                  ? '✓ Terraform MCP live — provider hints enriched'
                  : 'Terraform MCP offline — using built-in provider hints'}
                {result.terraform_mcp.provider_hints && (
                  <span className="ml-2 text-regent-400">({result.terraform_mcp.provider_hints})</span>
                )}
              </p>
            )}
          </div>

          {/* Security findings */}
          {result.security_review.finding_count > 0 ? (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold" style={{ color: 'var(--rc-text-1)' }}>
                Security review ({result.security_review.finding_count} finding{result.security_review.finding_count !== 1 ? 's' : ''})
              </h3>
              {result.security_review.findings.map(f => (
                <FindingCard
                  key={f.id}
                  f={f}
                  expanded={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                />
              ))}
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-green-900/20 border border-green-800 text-sm text-green-300">
              Security review passed — generated module uses secure-by-default settings throughout.
            </div>
          )}

          {/* Deploy instructions */}
          {result.plan?.deploy_steps?.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--rc-text-1)' }}>
                <Terminal className="w-4 h-4" />
                Deploy instructions
              </h3>
              <div className="p-4 rounded-lg border border-white/10 bg-[var(--rc-bg-elevated)] space-y-2.5">
                {result.plan.deploy_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <span className="text-xs font-mono text-regent-400 flex-shrink-0 mt-0.5 w-4">{i + 1}.</span>
                    <code className="text-xs font-mono flex-1 leading-relaxed" style={{ color: 'var(--rc-text-1)' }}>{step}</code>
                    <CopyButton text={step} />
                  </div>
                ))}
              </div>
            </div>
          )}

          <p className="text-xs" style={{ color: 'var(--rc-text-3)' }}>
            Built in {result.execution_time_ms}ms · {result.build_id}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'build',      label: 'Build',        icon: Hammer        },
  { id: 'review',     label: 'Review',       icon: FileSearch    },
  { id: 'generate',   label: 'Generate',     icon: Wand2         },
  { id: 'plan',       label: 'Plan Analysis',icon: BarChart3     },
  { id: 'findings',   label: 'Findings',     icon: ClipboardList },
  { id: 'compliance', label: 'Compliance',   icon: Code2         },
] as const;

type TabId = typeof TABS[number]['id'];

export default function TerraClawPage() {
  const [activeTab, setActiveTab] = useState<TabId>('build');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3" style={{ color: 'var(--rc-text-1)' }}>
            <Container className="text-orange-400" /> TerraClaw
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--rc-text-2)' }}>
            Terraform security governance — build modules from plain English, review HCL, and gate IaC with APPROVE / WARN / BLOCK decisions.
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-white/10">
        <nav className="flex gap-1 -mb-px overflow-x-auto">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === id
                  ? 'border-regent-500 text-regent-300'
                  : 'border-transparent hover:border-white/20'
              }`}
              style={activeTab !== id ? { color: 'var(--rc-text-2)' } : {}}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'build'      && <BuildTab />}
        {activeTab === 'review'     && <ReviewTab />}
        {activeTab === 'generate'   && <GenerateTab />}
        {activeTab === 'plan'       && <PlanTab />}
        {activeTab === 'findings'   && <FindingsTab />}
        {activeTab === 'compliance' && <ComplianceTab />}
      </div>
    </div>
  );
}

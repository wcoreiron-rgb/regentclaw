'use client';
import { useEffect, useState } from 'react';
import { Shield, CheckCircle, Eye, Lock, Layers, Zap, Package, Brain } from 'lucide-react';
import { apiFetch } from '@/lib/api';

const PRINCIPLES = [
  { icon: Shield, title: 'Every Component Has Identity', desc: 'No anonymous modules, agents, or integrations. Every entity is registered with an owner.' },
  { icon: Lock, title: 'Every Action Is Authorized', desc: 'No execution without policy validation. Actions are checked before they happen.' },
  { icon: Eye, title: 'Every Runtime Is Monitored', desc: 'Not just who the module is — but what it is doing right now, in real time.' },
  { icon: CheckCircle, title: 'Every Workflow Is Attributable', desc: 'All actions map to a human owner, business function, or approved automation.' },
  { icon: Zap, title: 'Every Risk Is Containable', desc: 'Immediate isolation, revocation, or blocking when risk is detected.' },
  { icon: Layers, title: 'Every Module Is Governed', desc: 'Plug-and-play does not mean plug-and-uncontrolled. Governance is built in.' },
];

export default function TrustFabricPage() {
  const [agtStatus, setAgtStatus] = useState<any>(null);

  useEffect(() => {
    apiFetch<any>('/dashboard/agt-status').then(setAgtStatus).catch(console.error);
  }, []);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Shield className="text-regent-400" /> Trust Fabric
        </h1>
        <p className="text-gray-400 mt-1">Zero Trust Enforcement Layer — Two-layer architecture: Microsoft AGT + RegentClaw</p>
      </div>

      {/* Two-layer architecture banner */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* AGT Layer */}
        <div className="bg-blue-900/20 border border-blue-700/40 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Package className="w-5 h-5 text-blue-400" />
            <h2 className="font-semibold text-blue-300">Microsoft AGT Layer</h2>
            <span className={`ml-auto text-xs px-2 py-0.5 rounded-full font-medium ${agtStatus?.agt_available ? 'bg-green-900/50 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
              {agtStatus ? (agtStatus.agt_available ? `v${agtStatus.version} Active` : 'Not loaded') : '…'}
            </span>
          </div>
          <p className="text-xs text-gray-400 mb-3">Compliance, scanning, and audit intelligence layer</p>
          <div className="space-y-1.5">
            {[
              { label: 'Prompt Defense Evaluator', sub: '12-vector injection audit → ArcClaw', key: 'prompt_defense' },
              { label: 'Supply Chain Guard', sub: 'Typosquatting + drift → module registration', key: 'supply_chain_guard' },
              { label: 'Security Scanner', sub: 'Directory scanning → skill/module trust', key: 'security_scanner' },
            ].map(({ label, sub, key }) => (
              <div key={key} className="flex items-start gap-2 text-sm">
                <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${agtStatus?.capabilities?.[key] ? 'bg-green-400' : 'bg-gray-600'}`} />
                <div>
                  <p className="text-gray-200">{label}</p>
                  <p className="text-xs text-gray-500">{sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* RegentClaw Runtime Layer */}
        <div className="bg-regent-900/20 border border-regent-700/40 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5 text-regent-400" />
            <h2 className="font-semibold text-regent-300">RegentClaw Trust Fabric</h2>
            <span className="ml-auto text-xs px-2 py-0.5 rounded-full font-medium bg-green-900/50 text-green-400">Active</span>
          </div>
          <p className="text-xs text-gray-400 mb-3">Runtime enforcement — handles what AGT Python does not</p>
          <div className="space-y-1.5">
            {[
              { label: 'Runtime Policy Enforcement', sub: 'Deterministic action mediation (sub-ms)' },
              { label: 'Execution Sandboxing', sub: 'Module isolation + blast radius control' },
              { label: 'Zero-Trust Identity Runtime', sub: 'Continuous verification per action' },
              { label: 'Anomaly Detection', sub: 'Rule-based + threshold behavioral analysis' },
              { label: 'Containment & Kill Switch', sub: 'Isolate module, revoke connector, suspend identity' },
            ].map(({ label, sub }) => (
              <div key={label} className="flex items-start gap-2 text-sm">
                <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0 bg-regent-400" />
                <div>
                  <p className="text-gray-200">{label}</p>
                  <p className="text-xs text-gray-500">{sub}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* AGT Note */}
      {agtStatus && (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-4 text-sm text-gray-400">
          <p className="text-gray-300 font-medium mb-1">Architecture Note</p>
          <p>{agtStatus.note}</p>
          <p className="mt-2 text-regent-400">Runtime enforcement: <span className="text-white">{agtStatus.runtime_enforcement}</span></p>
        </div>
      )}

      {/* Core Principles */}
      <div>
        <h2 className="font-semibold text-white mb-4">Zero Trust Principles</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PRINCIPLES.map(({ icon: Icon, title, desc }) => (
            <div key={title} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <Icon className="w-6 h-6 text-regent-400 mb-3" />
              <h3 className="font-semibold text-white mb-1">{title}</h3>
              <p className="text-sm text-gray-400">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Action flow */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="font-semibold text-white mb-4">Action Evaluation Flow</h2>
        <div className="flex flex-wrap gap-2 items-center text-sm">
          {[
            'Action Request',
            'AGT Prompt Scan',
            'AGT Supply Chain Check',
            'Identity Verification',
            'Policy Evaluation',
            'Anomaly Detection',
            'Risk Scoring',
            'Decision (Allow / Block)',
            'Audit Log',
          ].map((step, i, arr) => (
            <span key={step} className="flex items-center gap-2">
              <span className={`px-3 py-1.5 rounded-lg border text-gray-200 ${step.startsWith('AGT') ? 'bg-blue-900/30 border-blue-700/50' : 'bg-gray-800 border-gray-700'}`}>
                {step}
              </span>
              {i < arr.length - 1 && <span className="text-gray-600">→</span>}
            </span>
          ))}
        </div>
        <p className="text-xs text-gray-500 mt-3">Blue steps = Microsoft AGT · Gray steps = RegentClaw Trust Fabric</p>
      </div>
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { Settings, Cpu, Database, Key, Server, RefreshCw } from 'lucide-react';
import type { HealthStatus } from '../types';

export const SettingsView: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (e) {
      console.error("Fetch health error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="space-y-6 pb-16 max-w-5xl mx-auto">
      
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" /> System Health & API Integrations
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Status of offline knowledge indexes, LLM extractors, and authoritative security APIs.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Health</span>
        </button>
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* Groq API */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" /> Groq LLM API
            </span>
            {health?.services.groq_api.configured ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                CONFIGURED
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
                OPTIONAL (OLLAMA FALLBACK)
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300">
            Model: <span className="font-mono text-cyan-400">{health?.services.groq_api.model || 'llama-3.3-70b-versatile'}</span>
          </p>
          <p className="text-[11px] text-slate-500">
            Used for ultra-fast primary claim extraction and self-consistency checking.
          </p>
        </div>

        {/* Ollama Local Fallback */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Server className="w-4 h-4 text-emerald-400" /> Ollama Offline LLM
            </span>
            {health?.services.ollama.reachable ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                REACHABLE
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
                STANDBY / REGEX ACTIVE
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300">
            Endpoint: <span className="font-mono text-slate-400">{health?.services.ollama.url}</span>
          </p>
          <p className="text-[11px] text-slate-500">
            Automatic zero-cost offline air-gapped fallback when GROQ_API_KEY is not set.
          </p>
        </div>

        {/* NVD API */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" /> NVD CVE Database
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-300">
            Cache Items: <span className="font-mono text-cyan-400">{health?.services.nvd_api.cache_items || 0}</span>
          </p>
          <p className="text-[11px] text-slate-500">
            Authoritative NIST NVD REST API v2.0 with local 24h TTLCache.
          </p>
        </div>

        {/* MITRE ATT&CK STIX */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" /> MITRE ATT&CK Enterprise
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              INDEXED
            </span>
          </div>
          <p className="text-xs text-slate-300">
            Techniques Indexed: <span className="font-mono text-emerald-400">{health?.services.mitre_database.techniques_indexed || 0}</span>
          </p>
          <p className="text-[11px] text-slate-500">
            Offline SQLite database loaded from MITRE Enterprise STIX bundle.
          </p>
        </div>

        {/* SigmaHQ Rules */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Database className="w-4 h-4 text-amber-400" /> SigmaHQ Rules Index
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              INDEXED
            </span>
          </div>
          <p className="text-xs text-slate-300">
            Rules Indexed: <span className="font-mono text-amber-400">{health?.services.sigma_database.rules_indexed || 0}</span>
          </p>
          <p className="text-[11px] text-slate-500">
            Local rule mirror synced from official SigmaHQ repository.
          </p>
        </div>

        {/* Threat Intel APIs */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-slate-400 uppercase font-semibold flex items-center gap-2">
              <Key className="w-4 h-4 text-purple-400" /> Threat Intel (AbuseIPDB / VT)
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
              OPTIONAL
            </span>
          </div>
          <p className="text-xs text-slate-300">
            AbuseIPDB: {health?.services.abuseipdb.configured ? '✓ Configured' : '— Not set'} • VirusTotal: {health?.services.virustotal.configured ? '✓ Configured' : '— Not set'}
          </p>
          <p className="text-[11px] text-slate-500">
            Free-tier API keys can be set in <code className="text-cyan-400">.env</code> file.
          </p>
        </div>

      </div>

    </div>
  );
};

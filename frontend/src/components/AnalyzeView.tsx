import React, { useState, useRef } from 'react';
import { 
  Play, ShieldCheck, ShieldAlert, AlertOctagon, FileText, ExternalLink, 
  ChevronDown, ChevronUp, Download, Sparkles, RefreshCw, CheckCircle
} from 'lucide-react';
import type { ClaimResult, AnalysisSummary, VerdictType } from '../types';

const SAMPLE_PRESETS = [
  {
    label: "Mixed Real & Fabricated CVEs",
    text: `SECURITY INCIDENT REPORT & VULNERABILITY ANALYSIS:

During SOC log inspection, our team identified suspicious exploitation attempts targeting Palo Alto Networks gateways via CVE-2024-3400 (CVSS 10.0).

Additionally, the attacker attempted to leverage CVE-2099-99999 for privilege escalation and claimed zero-day CVE-2024-998877 on Windows endpoints.

MITRE ATT&CK techniques observed include Command Interpreter (T1059.001) and fabricated technique T9999.001.

Sigma rule matched: "PowerShell Download Cradle".`
  },
  {
    label: "Log Analysis & MITRE Audit",
    text: `INCIDENT SUMMARY:
Adversary executed T1566 (Phishing) to gain initial foothold, followed by credential dumping via T1003.001 (LSASS Memory).

Attacker also claimed technique T8888.123 for quantum persistence and executed CVE-2021-44228 (Log4Shell).`
  },
  {
    label: "Pure Valid Security Claims",
    text: `VULNERABILITY DISCLOSURE:
Critical flaw CVE-2023-34362 affects MOVEit Transfer. Attackers utilized T1190 (Exploit Public-Facing Application) to execute malicious PowerShell cradles matching Sigma rule "Mimikatz Command Line Arguments".`
  }
];

export const AnalyzeView: React.FC = () => {
  const [inputText, setInputText] = useState(SAMPLE_PRESETS[0].text);
  const [contextText, setContextText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [streamClaims, setStreamClaims] = useState<ClaimResult[]>([]);
  const [summary, setSummary] = useState<AnalysisSummary | null>(null);
  const [expandedCard, setExpandedCard] = useState<string | null>(null);
  const [activeModalEvidence, setActiveModalEvidence] = useState<any | null>(null);

  const claimsEndRef = useRef<HTMLDivElement>(null);

  const handleRunAnalysis = async () => {
    if (!inputText.trim()) return;

    setIsAnalyzing(true);
    setStreamClaims([]);
    setSummary(null);

    try {
      const response = await fetch('/api/analyze?stream=true', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream',
        },
        body: JSON.stringify({
          text: inputText,
          context: contextText || null,
        }),
      });

      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const parsed = JSON.parse(line);
            if (parsed.event === "claim_validated") {
              setStreamClaims((prev) => [...prev, parsed.data]);
              claimsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
            } else if (parsed.event === "summary") {
              setSummary(parsed.data);
            }
          } catch (e) {
            console.warn("Error parsing SSE line:", line);
          }
        }
      }
    } catch (err) {
      console.error("Analysis stream error:", err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedCard(expandedCard === id ? null : id);
  };

  const getVerdictBadge = (verdict: VerdictType) => {
    switch (verdict) {
      case 'PASS':
        return (
          <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3.5 h-3.5 mr-1 text-emerald-400" /> PASS
          </span>
        );
      case 'FLAG':
        return (
          <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <ShieldAlert className="w-3.5 h-3.5 mr-1 text-amber-400" /> FLAG
          </span>
        );
      case 'BLOCK':
        return (
          <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <AlertOctagon className="w-3.5 h-3.5 mr-1 text-rose-400" /> BLOCK
          </span>
        );
    }
  };

  const fetchEvidenceModal = async (evidenceId: string) => {
    const rawId = evidenceId.replace("sha256:", "");
    try {
      const res = await fetch(`/audit/evidence_${rawId}.json`);
      if (res.ok) {
        const json = await res.json();
        setActiveModalEvidence(json);
      }
    } catch (e) {
      console.error("Error fetching evidence packet:", e);
    }
  };

  return (
    <div className="space-y-8 pb-16">
      
      {/* Top Banner & Sample Presets */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 bg-slate-900/60 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400" /> Security LLM Output Interceptor & Firewall
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              Paste raw security report text or LLM responses below to extract claims and validate against NVD, MITRE ATT&CK, & SigmaHQ in real time.
            </p>
          </div>
          
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Sample Prompts:</span>
            {SAMPLE_PRESETS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => setInputText(preset.text)}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input Textarea Area */}
        <div className="mt-6 space-y-4">
          <div>
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-2">
              Pasted LLM Output / Security Claim Text
            </label>
            <textarea
              rows={6}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Paste raw LLM text containing CVEs, MITRE technique IDs, Sigma rules, or IOCs..."
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition shadow-inner resize-y"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
            <div className="md:col-span-2">
              <input
                type="text"
                value={contextText}
                onChange={(e) => setContextText(e.target.value)}
                placeholder="Optional ground truth context (for faithfulness scoring)..."
                className="w-full px-4 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleRunAnalysis}
              disabled={isAnalyzing || !inputText.trim()}
              className="w-full flex items-center justify-center space-x-2 px-6 py-3 rounded-xl font-semibold text-sm bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition transform active:scale-95 cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Validating Security Claims...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current text-slate-950" />
                  <span>Intercept & Interrogate Output</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Summary Gauge & Risk Score Header */}
      {summary && (
        <div className={`glass-panel p-6 rounded-2xl border transition-all ${
          summary.verdict === 'BLOCK' 
            ? 'border-rose-500/40 bg-rose-950/20 glow-rose' 
            : summary.verdict === 'FLAG'
            ? 'border-amber-500/40 bg-amber-950/20 glow-amber'
            : 'border-emerald-500/40 bg-emerald-950/20 glow-emerald'
        }`}>
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            
            <div className="flex items-center space-x-4">
              <div className={`p-4 rounded-2xl ${
                summary.verdict === 'BLOCK' ? 'bg-rose-500/20 text-rose-400' :
                summary.verdict === 'FLAG' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                {summary.verdict === 'BLOCK' ? <AlertOctagon className="w-10 h-10" /> :
                 summary.verdict === 'FLAG' ? <ShieldAlert className="w-10 h-10" /> : <ShieldCheck className="w-10 h-10" />}
              </div>
              <div>
                <div className="flex items-center space-x-3">
                  <h3 className="text-2xl font-extrabold text-slate-100">
                    DOCUMENT VERDICT: {summary.verdict}
                  </h3>
                  {getVerdictBadge(summary.verdict)}
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  Analysis ID: <span className="font-mono text-cyan-400">{summary.analysis_id}</span> • Audited {summary.total_claims} claim(s).
                </p>
              </div>
            </div>

            {/* Score Metrics pill */}
            <div className="grid grid-cols-4 gap-4 text-center bg-slate-950/60 p-4 rounded-xl border border-slate-800/80 w-full md:w-auto">
              <div>
                <div className="text-xs text-slate-400 font-mono uppercase">Total</div>
                <div className="text-xl font-bold text-slate-100">{summary.total_claims}</div>
              </div>
              <div>
                <div className="text-xs text-emerald-400 font-mono uppercase">Pass</div>
                <div className="text-xl font-bold text-emerald-400">{summary.pass_count}</div>
              </div>
              <div>
                <div className="text-xs text-amber-400 font-mono uppercase">Flag</div>
                <div className="text-xl font-bold text-amber-400">{summary.flag_count}</div>
              </div>
              <div>
                <div className="text-xs text-rose-400 font-mono uppercase">Blocked</div>
                <div className="text-xl font-bold text-rose-400">{summary.block_count}</div>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* Real-time Claims Stream List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" /> Extracted Claim Timeline & Audit Evidence
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            {streamClaims.length} claim(s) validated
          </span>
        </div>

        {streamClaims.length === 0 && !isAnalyzing && (
          <div className="glass-panel p-12 text-center rounded-2xl border border-slate-800">
            <ShieldCheck className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 text-sm">No security claims analyzed yet. Paste text above and click Intercept.</p>
          </div>
        )}

        <div className="space-y-3">
          {streamClaims.map((res, index) => {
            const cardId = `card-${index}`;
            const isExpanded = expandedCard === cardId;

            return (
              <div
                key={index}
                className={`glass-panel rounded-xl border transition-all duration-200 ${
                  res.verdict === 'BLOCK' ? 'border-rose-900/40 bg-slate-900/80 hover:border-rose-500/50' :
                  res.verdict === 'FLAG' ? 'border-amber-900/40 bg-slate-900/80 hover:border-amber-500/50' :
                  'border-emerald-900/40 bg-slate-900/80 hover:border-emerald-500/50'
                }`}
              >
                {/* Card Header */}
                <div 
                  onClick={() => toggleExpand(cardId)}
                  className="p-4 flex items-center justify-between cursor-pointer select-none"
                >
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-xs font-semibold uppercase px-2.5 py-1 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                      {res.claim.type}
                    </span>
                    <span className="font-mono font-bold text-slate-100 text-sm">
                      {res.claim.value}
                    </span>
                    {getVerdictBadge(res.verdict)}
                  </div>

                  <div className="flex items-center space-x-4">
                    <div className="hidden sm:block text-right">
                      <div className="text-xs font-mono text-slate-400">
                        Risk Score: <span className={res.risk_score > 0.5 ? 'text-rose-400' : 'text-emerald-400'}>{res.risk_score}</span>
                      </div>
                    </div>
                    {isExpanded ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                  </div>
                </div>

                {/* Card Details (Expandable) */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 bg-slate-950/40 rounded-b-xl space-y-4 text-xs">
                    
                    {/* Raw Span */}
                    <div>
                      <span className="text-slate-500 font-mono uppercase text-[10px]">Exact Substring Span:</span>
                      <p className="font-mono text-slate-300 bg-slate-900 p-2 rounded border border-slate-800 mt-1">
                        "{res.claim.raw_span}"
                      </p>
                    </div>

                    {/* Deterministic Validation Details */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                        <span className="text-slate-400 font-mono font-semibold">Authoritative Source:</span>
                        <div className="text-slate-200">{res.deterministic.source}</div>
                        <div className="text-slate-400 mt-1">{res.deterministic.message}</div>
                      </div>

                      <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 space-y-2">
                        <span className="text-slate-400 font-mono font-semibold">Semantic Scores:</span>
                        <div className="flex justify-between items-center text-slate-300 font-mono">
                          <span>Consistency Score:</span>
                          <span className="text-cyan-400">{(res.consistency_score * 100).toFixed(0)}%</span>
                        </div>
                        <div className="flex justify-between items-center text-slate-300 font-mono">
                          <span>Faithfulness Score:</span>
                          <span className="text-emerald-400">{(res.faithfulness_score * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                    </div>

                    {/* Citations & Evidence Packet Link */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800">
                      <div className="flex items-center space-x-2">
                        {res.citations.map((url, i) => (
                          <a
                            key={i}
                            href={url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-mono underline"
                          >
                            <span>Official Documentation</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        ))}
                      </div>

                      <button
                        onClick={() => fetchEvidenceModal(res.evidence_id)}
                        className="inline-flex items-center space-x-1 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[11px] transition"
                      >
                        <Download className="w-3 h-3 text-cyan-400" />
                        <span>Audit Packet ({res.evidence_id})</span>
                      </button>
                    </div>

                  </div>
                )}
              </div>
            );
          })}
          <div ref={claimsEndRef} />
        </div>
      </div>

      {/* Modal for Audit Evidence JSON */}
      {activeModalEvidence && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-2xl p-6 rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-mono text-sm font-bold text-slate-100 flex items-center gap-2">
                <Download className="w-4 h-4 text-cyan-400" /> SHA-256 Signed Evidence Packet
              </h3>
              <button
                onClick={() => setActiveModalEvidence(null)}
                className="text-slate-400 hover:text-slate-100 font-bold px-2 py-1 text-lg"
              >
                ✕
              </button>
            </div>
            
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-cyan-300 font-mono text-xs max-h-96 overflow-y-auto">
              {JSON.stringify(activeModalEvidence, null, 2)}
            </pre>

            <div className="flex justify-end">
              <button
                onClick={() => setActiveModalEvidence(null)}
                className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-semibold text-xs"
              >
                Close Audit View
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

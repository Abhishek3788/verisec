import React, { useEffect, useState } from 'react';
import { History, Search, Trash2, Eye } from 'lucide-react';
import type { HistoryItem, AnalysisSummary } from '../types';

export const HistoryView: React.FC = () => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<AnalysisSummary | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (e) {
      console.error("Error fetching history:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Delete audit record ${id}?`)) return;

    try {
      const res = await fetch(`/api/history/${id}`, { method: 'DELETE' });
      if (res.ok) {
        setHistory((prev) => prev.filter((item) => item.id !== id));
      }
    } catch (err) {
      console.error("Delete error:", err);
    }
  };

  const inspectRecord = async (id: string) => {
    try {
      const res = await fetch(`/api/history/${id}`);
      if (res.ok) {
        const data = await res.json();
        setSelectedRecord(data);
      }
    } catch (err) {
      console.error("Fetch record error:", err);
    }
  };

  const filtered = history.filter((item) => 
    item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.text_snippet.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-16">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" /> Audit Log & Analysis History
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Persisted SQLite audit ledger of past LLM claim verifications and hallucination verdicts.
          </p>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Filter history..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* History Table */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/90 text-slate-400 uppercase font-mono tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-4">Analysis ID</th>
                <th className="p-4">Timestamp</th>
                <th className="p-4">Text Snippet</th>
                <th className="p-4 text-center">Claims</th>
                <th className="p-4 text-center">Pass / Flag / Block</th>
                <th className="p-4 text-center">Verdict</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    Loading audit history...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No past audit records found.
                  </td>
                </tr>
              ) : (
                filtered.map((item) => (
                  <tr 
                    key={item.id} 
                    onClick={() => inspectRecord(item.id)}
                    className="hover:bg-slate-900/60 cursor-pointer transition"
                  >
                    <td className="p-4 font-bold text-cyan-400">{item.id}</td>
                    <td className="p-4 text-slate-400">
                      {new Date(item.timestamp).toLocaleString()}
                    </td>
                    <td className="p-4 max-w-xs truncate text-slate-300 font-sans">
                      {item.text_snippet}
                    </td>
                    <td className="p-4 text-center font-bold text-slate-200">{item.total_claims}</td>
                    <td className="p-4 text-center">
                      <span className="text-emerald-400">{item.pass_count}</span> / {' '}
                      <span className="text-amber-400">{item.flag_count}</span> / {' '}
                      <span className="text-rose-400">{item.block_count}</span>
                    </td>
                    <td className="p-4 text-center">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        item.verdict === 'BLOCK' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' :
                        item.verdict === 'FLAG' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                        'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {item.verdict}
                      </span>
                    </td>
                    <td className="p-4 text-right space-x-2">
                      <button 
                        onClick={(e) => { e.stopPropagation(); inspectRecord(item.id); }}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400"
                        title="View Full Report"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      <button 
                        onClick={(e) => handleDelete(item.id, e)}
                        className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-rose-400"
                        title="Delete Record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Record Inspection Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel w-full max-w-3xl p-6 rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="font-bold text-slate-100 text-base">
                  Audit Report: {selectedRecord.analysis_id}
                </h3>
                <span className="text-xs font-mono text-slate-400">
                  {new Date(selectedRecord.timestamp).toLocaleString()}
                </span>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="text-slate-400 hover:text-slate-100 font-bold px-2 py-1 text-lg"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                <span className="text-slate-500 uppercase text-[10px]">Claims Audited:</span>
                <div className="mt-1 font-bold text-slate-200">
                  Total: {selectedRecord.total_claims} | Pass: {selectedRecord.pass_count} | Flag: {selectedRecord.flag_count} | Block: {selectedRecord.block_count}
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-slate-400 font-bold uppercase text-[10px]">Validated Claims:</span>
                {selectedRecord.claims.map((c, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-cyan-400">[{c.claim.type}] {c.claim.value}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        c.verdict === 'BLOCK' ? 'bg-rose-500/20 text-rose-400' :
                        c.verdict === 'FLAG' ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {c.verdict}
                      </span>
                    </div>
                    <p className="text-slate-400">{c.deterministic.message}</p>
                    <div className="text-[10px] text-slate-500">Evidence ID: {c.evidence_id}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-200 text-xs font-semibold"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

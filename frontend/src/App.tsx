import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { AnalyzeView } from './components/AnalyzeView';
import { HistoryView } from './components/HistoryView';
import { DashboardView } from './components/DashboardView';
import { SettingsView } from './components/SettingsView';
import type { HealthStatus } from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<'analyze' | 'history' | 'dashboard' | 'settings'>('analyze');
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    const checkHealth = () => {
      fetch('/api/health')
        .then((res) => res.json())
        .then((data) => setHealth(data))
        .catch(() => setHealth(null));
    };

    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} health={health} />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        {activeTab === 'analyze' && <AnalyzeView />}
        {activeTab === 'history' && <HistoryView />}
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'settings' && <SettingsView />}
      </main>

      {/* Footer */}
      <footer className="glass-panel border-t border-slate-900 bg-slate-950 py-4 text-center text-xs font-mono text-slate-500">
        VeriSec v1.0.0 — LLM Hallucination Firewall for Security Teams • 100% Free & Open Source
      </footer>

    </div>
  );
}

export default App;

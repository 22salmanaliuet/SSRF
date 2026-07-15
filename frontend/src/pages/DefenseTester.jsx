import React, { useState } from 'react';
import axios from 'axios';
import { ShieldCheck, ArrowRight, ShieldAlert } from 'lucide-react';

const DefenseTester = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000/safe-fetch?url=FUZZ');
  const [defenses, setDefenses] = useState({
    allowlist: true,
    blockPrivate: true,
    noRedirects: false,
    sanitizeHeaders: false,
    dnsRebind: true,
  });
  
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const toggleDefense = (key) => {
    setDefenses(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const runTest = async () => {
    setLoading(true);
    try {
      const activeDefenses = Object.entries(defenses)
        .filter(([_, isActive]) => isActive)
        .map(([key, _]) => key);
        
      const res = await axios.post('http://localhost:8000/defense/test', {
        target_url: targetUrl,
        defenses: activeDefenses
      });
      
      setResults(res.data.results);
    } catch (err) {
      console.error(err);
      alert('Failed to run defense test');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Defense Tester</h1>
        <p className="text-gray-400 mt-2">Evaluate SSRF mitigations by running the framework against protected endpoints.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-6">
          <div className="bg-card p-6 rounded-xl border border-gray-800">
            <h3 className="font-semibold mb-4 text-lg">Test Configuration</h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Target URL</label>
                <input 
                  type="text" 
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="w-full bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-3">Simulated Defenses (Lab Mode)</label>
                <div className="space-y-3">
                  {Object.entries({
                    allowlist: 'URL Allowlist Validation',
                    blockPrivate: 'Block Private IP Ranges',
                    noRedirects: 'Disable HTTP Redirects',
                    sanitizeHeaders: 'Header Sanitization',
                    dnsRebind: 'DNS Rebinding Protection'
                  }).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-3 cursor-pointer group">
                      <div className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                        defenses[key] ? 'bg-primary border-primary' : 'bg-[#0a0c10] border-gray-600 group-hover:border-primary'
                      }`}>
                        {defenses[key] && <ShieldCheck size={14} className="text-white" />}
                      </div>
                      <span className="text-sm text-gray-300 group-hover:text-white transition-colors">{label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <button 
                onClick={runTest}
                disabled={loading}
                className="w-full bg-primary hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-400 text-white flex items-center justify-center gap-2 py-2 rounded-lg font-medium transition-colors mt-6"
              >
                {loading ? 'Testing...' : 'Run Defense Analysis'} <ArrowRight size={18} />
              </button>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2">
          {results ? (
            <div className="bg-card rounded-xl border border-gray-800 overflow-hidden h-full flex flex-col">
              <div className="p-4 border-b border-gray-800 bg-[#151821]">
                <h3 className="font-semibold text-lg flex items-center gap-2">
                  <ShieldAlert className={results.length > 0 ? "text-yellow-500" : "text-green-500"} />
                  Analysis Results
                </h3>
              </div>
              <div className="p-6 flex-1 bg-[#0a0c10]">
                {results.length > 0 ? (
                  <div className="space-y-4">
                    <p className="text-yellow-400 mb-4 font-medium">Bypasses detected despite active defenses!</p>
                    {results.map((r, i) => (
                      <div key={i} className="p-4 rounded-lg bg-gray-800/50 border border-gray-700">
                        <div className="flex justify-between items-start mb-2">
                          <code className="text-primary text-sm font-mono">{r.payload}</code>
                          <span className="px-2 py-1 bg-red-500/20 text-red-500 text-xs font-bold rounded">BYPASSED</span>
                        </div>
                        <p className="text-sm text-gray-300">{r.evidence}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center space-y-4 py-12">
                    <div className="w-16 h-16 rounded-full bg-green-500/20 flex items-center justify-center border border-green-500/50">
                      <ShieldCheck size={32} className="text-green-500" />
                    </div>
                    <div>
                      <h4 className="text-xl font-bold text-green-500">Fully Protected</h4>
                      <p className="text-gray-400 max-w-md mt-2">The selected mitigations successfully blocked all tested SSRF payloads.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-card rounded-xl border border-gray-800 border-dashed flex items-center justify-center h-full min-h-[400px]">
              <p className="text-gray-500 flex flex-col items-center gap-2">
                <ShieldAlert size={32} />
                Configure and run a test to see results
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DefenseTester;

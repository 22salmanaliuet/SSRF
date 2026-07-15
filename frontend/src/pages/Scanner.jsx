import React, { useState, useEffect } from 'react';
import axios from 'axios';
import LiveTerminal from '../components/LiveTerminal';
import { Play, Download, StopCircle } from 'lucide-react';

const SeverityBadge = ({ severity }) => {
  const colors = {
    CRITICAL: 'bg-red-500/20 text-red-500 border-red-500/50',
    HIGH: 'bg-orange-500/20 text-orange-500 border-orange-500/50',
    MEDIUM: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
    LOW: 'bg-blue-500/20 text-blue-500 border-blue-500/50',
    INFO: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
  };
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold border ${colors[severity.toUpperCase()] || colors.INFO}`}>
      {severity.toUpperCase()}
    </span>
  );
};

const Scanner = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000/fetch?url=FUZZ');
  const [scanMode, setScanMode] = useState('basic');
  const [logs, setLogs] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [status, setStatus] = useState('idle'); // idle, running, complete, error
  const [scanId, setScanId] = useState(null);
  const [ws, setWs] = useState(null);

  const startScan = async () => {
    try {
      setStatus('running');
      setLogs([]);
      setVulns([]);
      
      const res = await axios.post('http://localhost:8000/scan', {
        target_url: targetUrl,
        scan_mode: scanMode,
        timeout: 10,
        enable_blind_ssrf: false,
        enable_port_scan: false,
      });
      
      const id = res.data.scan_id;
      setScanId(id);
      
      const socket = new WebSocket(`ws://localhost:8000/scan/ws/${id}`);
      setWs(socket);
      
      socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        setLogs(prev => [...prev, data]);
        
        if (data.type === 'result') {
          setVulns(prev => [...prev, data.data]);
        } else if (data.type === 'done') {
          setStatus('complete');
          socket.close();
        } else if (data.type === 'error') {
          setStatus('error');
          socket.close();
        }
      };
      
      socket.onerror = () => {
        setStatus('error');
        setLogs(prev => [...prev, { type: 'error', message: 'WebSocket connection error' }]);
      };
      
    } catch (err) {
      setStatus('error');
      setLogs([{ type: 'error', message: err.message }]);
    }
  };
  
  const stopScan = () => {
    if (ws) {
      ws.close();
    }
    setStatus('complete');
  };

  const downloadJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(vulns, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", "scan_results.json");
    document.body.appendChild(downloadAnchorNode); // required for firefox
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Active Scanner</h1>
        <p className="text-gray-400 mt-2">Discover and exploit SSRF vulnerabilities in real-time.</p>
      </div>

      <div className="bg-card p-6 rounded-xl border border-gray-800">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div className="col-span-1 md:col-span-2">
            <label className="block text-sm font-medium text-gray-400 mb-1">Target URL</label>
            <input 
              type="text" 
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary"
              placeholder="http://target/?url=FUZZ"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Scan Mode</label>
            <select 
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value)}
              className="w-full bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary"
            >
              <option value="basic">Basic (Default payloads)</option>
              <option value="full">Full (All payloads)</option>
            </select>
          </div>
          <div>
            {status === 'running' ? (
              <button 
                onClick={stopScan}
                className="w-full bg-red-500/20 hover:bg-red-500/30 text-red-500 border border-red-500/50 flex items-center justify-center gap-2 py-2 rounded-lg font-medium transition-colors"
              >
                <StopCircle size={18} /> Stop Scan
              </button>
            ) : (
              <button 
                onClick={startScan}
                className="w-full bg-primary hover:bg-blue-600 text-white flex items-center justify-center gap-2 py-2 rounded-lg font-medium transition-colors"
              >
                <Play size={18} /> Start Scan
              </button>
            )}
          </div>
        </div>
      </div>

      <LiveTerminal logs={logs} />

      {vulns.length > 0 && (
        <div className="bg-card rounded-xl border border-gray-800 overflow-hidden">
          <div className="p-4 border-b border-gray-800 flex justify-between items-center bg-[#151821]">
            <h3 className="font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
              Vulnerabilities Found ({vulns.length})
            </h3>
            <button 
              onClick={downloadJSON}
              className="text-sm flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
            >
              <Download size={16} /> Export JSON
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-[#0a0c10] text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Payload</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {vulns.map((v, i) => (
                  <tr key={i} className="hover:bg-gray-800/20 transition-colors">
                    <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-primary">{v.payload}</td>
                    <td className="px-4 py-3">{v.response_code}</td>
                    <td className="px-4 py-3 text-gray-300">{v.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default Scanner;

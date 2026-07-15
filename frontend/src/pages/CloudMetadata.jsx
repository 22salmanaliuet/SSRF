import React, { useState } from 'react';
import axios from 'axios';
import { Cloud, Play, Copy, CheckCircle } from 'lucide-react';

const CloudMetadata = () => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000/fetch?url=FUZZ');
  const [provider, setProvider] = useState('all');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const runExtraction = async () => {
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post('http://localhost:8000/cloud/extract', {
        target_url: targetUrl,
        provider: provider
      });
      // Mocking result structure for UI demonstration since the backend just simulates it currently
      setResult({
        status: "success",
        provider: "AWS",
        endpoint: "http://169.254.169.254/latest/meta-data/",
        data: {
          "ami-id": "ami-0abcdef1234567890",
          "hostname": "ip-172-31-10-15.ec2.internal",
          "iam": {
            "info": {
              "InstanceProfileArn": "arn:aws:iam::123456789012:instance-profile/SSRF-Role",
              "InstanceProfileId": "AIPAXXXXXXXXXXXXXXXXX"
            },
            "security-credentials": {
              "SSRF-Role": {
                "Code": "Success",
                "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "IQoJb3JpZ2luX2VjEJv...EXAMPLE",
                "Expiration": "2026-07-15T15:00:00Z"
              }
            }
          }
        },
        message: res.data.message
      });
    } catch (err) {
      setResult({ status: 'error', error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const copyResult = () => {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Cloud Metadata Extractor</h1>
        <p className="text-gray-400 mt-2">Target and extract sensitive cloud instance metadata (AWS, GCP, Azure).</p>
      </div>

      <div className="bg-card p-6 rounded-xl border border-gray-800 flex flex-col md:flex-row gap-4 items-end">
        <div className="flex-1 w-full">
          <label className="block text-sm font-medium text-gray-400 mb-1">Target URL</label>
          <input 
            type="text" 
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary"
          />
        </div>
        <div className="w-full md:w-48">
          <label className="block text-sm font-medium text-gray-400 mb-1">Provider</label>
          <select 
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="w-full bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary"
          >
            <option value="all">Auto-Detect All</option>
            <option value="aws">AWS (EC2/ECS)</option>
            <option value="gcp">Google Cloud</option>
            <option value="azure">Azure</option>
          </select>
        </div>
        <button 
          onClick={runExtraction}
          disabled={loading}
          className="w-full md:w-auto bg-primary hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-400 text-white flex items-center justify-center gap-2 px-6 py-2 rounded-lg font-medium transition-colors"
        >
          <Cloud size={18} /> {loading ? 'Extracting...' : 'Extract Data'}
        </button>
      </div>

      {result && (
        <div className="bg-card rounded-xl border border-gray-800 overflow-hidden flex flex-col h-[500px]">
          <div className="p-4 border-b border-gray-800 bg-[#151821] flex justify-between items-center">
            <h3 className="font-semibold flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${result.status === 'error' ? 'bg-red-500' : 'bg-green-500'}`}></span>
              Extraction Results {result.provider && `(${result.provider})`}
            </h3>
            <button 
              onClick={copyResult}
              className="text-gray-400 hover:text-white p-1 rounded hover:bg-gray-700 transition-colors"
              title="Copy JSON"
            >
              {copied ? <CheckCircle size={18} className="text-green-500" /> : <Copy size={18} />}
            </button>
          </div>
          <div className="p-4 flex-1 bg-[#0a0c10] overflow-auto terminal-scroll">
            <pre className="text-sm font-mono text-green-400">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default CloudMetadata;

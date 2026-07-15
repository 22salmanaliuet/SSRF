import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Copy, CheckCircle } from 'lucide-react';

const PayloadLibrary = () => {
  const [categories, setCategories] = useState([]);
  const [payloads, setPayloads] = useState([]);
  const [activeTab, setActiveTab] = useState('all');
  const [copiedId, setCopiedId] = useState(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    // Fetch categories on mount
    axios.get('http://localhost:8000/payloads').then(res => {
      setCategories(res.data.categories);
      // Fetch all payloads initially
      fetchPayloads('all');
    }).catch(console.error);
  }, []);

  const fetchPayloads = (category) => {
    setActiveTab(category);
    axios.get(`http://localhost:8000/payloads/${category}`).then(res => {
      setPayloads(res.data);
    }).catch(console.error);
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredPayloads = payloads.filter(p => p.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Payload Library</h1>
        <p className="text-gray-400 mt-2">Browse and copy from SEDF's extensive built-in payload collection.</p>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between bg-card p-4 rounded-xl border border-gray-800">
        <div className="flex flex-wrap gap-2">
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => fetchPayloads(cat)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                activeTab === cat 
                  ? 'bg-primary text-white' 
                  : 'bg-[#0a0c10] text-gray-400 hover:text-white border border-gray-700'
              }`}
            >
              {cat.charAt(0).toUpperCase() + cat.slice(1)}
            </button>
          ))}
        </div>
        
        <input 
          type="text" 
          placeholder="Search payloads..." 
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white text-sm focus:outline-none focus:border-primary w-full sm:w-64"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {filteredPayloads.map((payload, idx) => (
          <div key={idx} className="bg-card p-4 rounded-xl border border-gray-800 flex flex-col justify-between group hover:border-gray-600 transition-colors">
            <div className="flex justify-between items-start mb-4">
              <span className="px-2 py-1 rounded bg-blue-500/20 text-blue-400 text-xs font-semibold border border-blue-500/30">
                {activeTab === 'all' ? 'MIXED' : activeTab.toUpperCase()}
              </span>
              <button 
                onClick={() => copyToClipboard(payload, idx)}
                className="text-gray-400 hover:text-white p-1 rounded hover:bg-gray-800 transition-colors"
                title="Copy to clipboard"
              >
                {copiedId === idx ? <CheckCircle size={16} className="text-green-500" /> : <Copy size={16} />}
              </button>
            </div>
            
            <div className="bg-[#0a0c10] p-3 rounded-lg border border-gray-800 overflow-x-auto terminal-scroll">
              <code className="text-sm font-mono text-primary whitespace-nowrap">{payload}</code>
            </div>
          </div>
        ))}
      </div>
      
      {filteredPayloads.length === 0 && (
        <div className="text-center py-12 bg-card rounded-xl border border-gray-800">
          <p className="text-gray-400">No payloads found matching your search.</p>
        </div>
      )}
    </div>
  );
};

export default PayloadLibrary;

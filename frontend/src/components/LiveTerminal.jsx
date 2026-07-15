import React, { useEffect, useRef } from 'react';

const LiveTerminal = ({ logs }) => {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getColorClass = (line) => {
    if (line.includes('[VULN]')) return 'text-green-500 font-bold';
    if (line.includes('error') || line.includes('Error') || line.includes('[!]')) return 'text-red-400';
    if (line.includes('Testing') || line.includes('Scanning')) return 'text-yellow-400';
    return 'text-gray-300';
  };

  return (
    <div 
      ref={scrollRef}
      className="bg-[#0a0c10] border border-gray-800 rounded-lg p-4 h-96 overflow-y-auto terminal-scroll font-mono text-sm"
    >
      {logs.length === 0 ? (
        <p className="text-gray-500 italic">Waiting for scan to start...</p>
      ) : (
        logs.map((log, i) => (
          <div key={i} className={`whitespace-pre-wrap mb-1 ${getColorClass(log.message)}`}>
            {log.message}
          </div>
        ))
      )}
    </div>
  );
};

export default LiveTerminal;

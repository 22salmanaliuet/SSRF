import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Download, Trash2, FileJson, AlertCircle } from 'lucide-react';

const Reports = () => {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const res = await axios.get('http://localhost:8000/reports');
      setReports(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const deleteReport = async (id) => {
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await axios.delete(`http://localhost:8000/reports/${id}`);
      fetchReports();
    } catch (err) {
      alert('Failed to delete report');
    }
  };

  const downloadReport = (id) => {
    window.open(`http://localhost:8000/reports/${id}/export?format=json`, '_blank');
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Scan Reports</h1>
        <p className="text-gray-400 mt-2">View and export historical scan results and vulnerability data.</p>
      </div>

      <div className="bg-card rounded-xl border border-gray-800 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-gray-400">Loading reports...</div>
        ) : reports.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-gray-500">
            <FileJson size={48} className="mb-4 opacity-50" />
            <p>No reports found.</p>
            <p className="text-sm mt-1">Run a scan to generate a report.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-[#0a0c10] text-gray-400 border-b border-gray-800 text-sm">
                <tr>
                  <th className="px-6 py-4 font-medium">Report File</th>
                  <th className="px-6 py-4 font-medium">Type</th>
                  <th className="px-6 py-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {reports.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-800/20 transition-colors">
                    <td className="px-6 py-4 font-medium text-primary flex items-center gap-3">
                      <FileJson size={18} /> {r.name}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-400">JSON</td>
                    <td className="px-6 py-4 flex justify-end gap-3">
                      <button 
                        onClick={() => downloadReport(r.id)}
                        className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
                        title="Download JSON"
                      >
                        <Download size={18} />
                      </button>
                      <button 
                        onClick={() => deleteReport(r.id)}
                        className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-500/10 rounded transition-colors"
                        title="Delete Report"
                      >
                        <Trash2 size={18} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default Reports;

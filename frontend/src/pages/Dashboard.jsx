import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, Bug, Shield, BookOpen } from 'lucide-react';
import axios from 'axios';

const StatCard = ({ title, value, icon, color }) => (
  <div className="bg-card p-6 rounded-xl border border-gray-800 flex items-center justify-between">
    <div>
      <p className="text-gray-400 text-sm font-medium mb-1">{title}</p>
      <h3 className="text-3xl font-bold">{value}</h3>
    </div>
    <div className={`p-4 rounded-lg bg-${color}/10 text-${color}`}>
      {icon}
    </div>
  </div>
);

const Dashboard = () => {
  const navigate = useNavigate();
  const [reports, setReports] = useState([]);
  const [payloadCount, setPayloadCount] = useState(0);
  const [vulnCount, setVulnCount] = useState(0);
  const [defenseCount, setDefenseCount] = useState(0);

  const [chartData, setChartData] = useState([
    { name: 'Critical', value: 0, fill: '#ef4444' },
    { name: 'High', value: 0, fill: '#f97316' },
    { name: 'Medium', value: 0, fill: '#eab308' },
    { name: 'Low', value: 0, fill: '#0ea5e9' }
  ]);

  useEffect(() => {
    axios.get('http://localhost:8000/reports').then(res => {
      const data = res.data || [];
      setReports(data);
      
      let totalVulns = 0;
      let sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      
      data.forEach(report => {
        if (report.total_findings) {
          totalVulns += report.total_findings;
        }
        if (report.severities) {
          sevCounts.CRITICAL += (report.severities.CRITICAL || 0);
          sevCounts.HIGH += (report.severities.HIGH || 0);
          sevCounts.MEDIUM += (report.severities.MEDIUM || 0);
          sevCounts.LOW += (report.severities.LOW || 0);
        }
      });
      setVulnCount(totalVulns);
      setChartData([
        { name: 'Critical', value: sevCounts.CRITICAL, fill: '#ef4444' },
        { name: 'High', value: sevCounts.HIGH, fill: '#f97316' },
        { name: 'Medium', value: sevCounts.MEDIUM, fill: '#eab308' },
        { name: 'Low', value: sevCounts.LOW, fill: '#0ea5e9' }
      ]);
      // Count defenses tested based on report names (e.g. if they contain defense)
      // Or just leave at 0 until a real defense test runs.
    }).catch(console.error);

    axios.get('http://localhost:8000/payloads').then(res => {
      if(res.data && res.data.count) setPayloadCount(res.data.count);
    }).catch(console.error);
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-gray-400 mt-2">SEDF Overview & Statistics</p>
        </div>
        <button 
          onClick={() => navigate('/scanner')}
          className="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors"
        >
          New Scan
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard title="Total Scans" value={reports.length} icon={<Activity size={24} />} color="blue-500" />
        <StatCard title="Vulns Found" value={vulnCount} icon={<Bug size={24} />} color="red-500" />
        <StatCard title="Payloads" value={payloadCount} icon={<BookOpen size={24} />} color="green-500" />
        <StatCard title="Defenses Tested" value={defenseCount} icon={<Shield size={24} />} color="purple-500" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-card p-6 rounded-xl border border-gray-800 lg:col-span-2">
          <h3 className="text-lg font-semibold mb-6">Vulnerabilities by Severity</h3>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData}>
                <XAxis dataKey="name" stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1a1d27', borderColor: '#374151' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-card p-6 rounded-xl border border-gray-800">
          <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
          <div className="space-y-4">
            {reports.slice(0, 5).map((r, i) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-gray-800/50">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-green-500"></div>
                  <span className="text-sm font-medium truncate w-32">{r.name}</span>
                </div>
                <span className="text-xs text-gray-400">Completed</span>
              </div>
            ))}
            {reports.length === 0 && (
              <p className="text-gray-400 text-sm text-center py-8">No recent scans.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

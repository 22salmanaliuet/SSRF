import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ScanSearch, 
  ShieldAlert, 
  Library, 
  FileText, 
  CloudRain,
  Target
} from 'lucide-react';

const Sidebar = () => {
  const navItems = [
    { path: '/', name: 'Dashboard', icon: <LayoutDashboard size={20} /> },
    { path: '/scanner', name: 'Scanner', icon: <ScanSearch size={20} /> },
    { path: '/exploiter', name: 'Active Exploiter', icon: <Target size={20} /> },
    { path: '/defense', name: 'Defense Tester', icon: <ShieldAlert size={20} /> },
    { path: '/payloads', name: 'Payload Library', icon: <Library size={20} /> },
    { path: '/reports', name: 'Reports', icon: <FileText size={20} /> },
    { path: '/cloud', name: 'Cloud Metadata', icon: <CloudRain size={20} /> },
  ];

  return (
    <div className="w-64 bg-card border-r border-gray-800 flex flex-col h-full">
      <div className="p-6">
        <h1 className="text-2xl font-bold tracking-wider text-primary">SEDF</h1>
        <p className="text-xs text-info mt-1 uppercase tracking-widest">SSRF Framework</p>
      </div>
      
      <nav className="flex-1 mt-6">
        <ul className="space-y-2 px-4">
          {navItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive 
                      ? 'bg-primary/10 text-primary' 
                      : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                  }`
                }
              >
                {item.icon}
                <span className="font-medium">{item.name}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      
      <div className="p-4 border-t border-gray-800 text-xs text-center text-gray-500">
        <p>SEDF v1.0.0</p>
        <p>FYP UET Peshawar</p>
      </div>
    </div>
  );
};

export default Sidebar;

import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import DefenseTester from './pages/DefenseTester';
import PayloadLibrary from './pages/PayloadLibrary';
import Reports from './pages/Reports';
import CloudMetadata from './pages/CloudMetadata';

function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-background text-white">
        <Sidebar />
        <div className="flex-1 overflow-auto p-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scanner" element={<Scanner />} />
            <Route path="/defense" element={<DefenseTester />} />
            <Route path="/payloads" element={<PayloadLibrary />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/cloud" element={<CloudMetadata />} />
          </Routes>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;

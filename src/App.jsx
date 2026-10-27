import React, { useState, useEffect } from 'react';
import { Shield, Key, Activity, Layers, RefreshCw } from 'lucide-react';
import Overview from './components/Overview';
import Project1CryptoVault from './components/Project1CryptoVault';
import Project2SecureTunnel from './components/Project2SecureTunnel';
import Project3Sentinel from './components/Project3Sentinel';

export default function App() {
  const [currentProject, setCurrentProject] = useState('overview'); // 'overview', 'project1', 'project2', 'project3'
  
  // Backend health status
  const [p1Online, setP1Online] = useState(false);
  const [p2Online, setP2Online] = useState(false);
  const [p3Online, setP3Online] = useState(false);

  const checkHealth = async () => {
    // Project 1
    try {
      const r1 = await fetch('http://localhost:5001/health');
      setP1Online(r1.ok);
    } catch {
      setP1Online(false);
    }
    // Project 2
    try {
      const r2 = await fetch('http://localhost:5002/health');
      setP2Online(r2.ok);
    } catch {
      setP2Online(false);
    }
    // Project 3
    try {
      const r3 = await fetch('http://localhost:5003/health');
      setP3Online(r3.ok);
    } catch {
      setP3Online(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      {/* Master Sticky Header */}
      <header className="master-header">
        <div className="header-inner">
          <div className="brand-section">
            <span className="brand-badge">KLH ALM-2</span>
            <div>
              <div className="brand-title">CyberSecurity & Cryptography Suite</div>
              <div className="brand-sub">Active Learning Management Project 2 • Unified Master Dashboard</div>
            </div>
          </div>

          {/* Navigation Buttons for the 3 Projects */}
          <nav className="nav-buttons">
            <button
              className={`nav-btn ${currentProject === 'overview' ? 'active' : ''}`}
              onClick={() => setCurrentProject('overview')}
            >
              <Layers size={16} /> Overview
            </button>
            <button
              className={`nav-btn p1 ${currentProject === 'project1' ? 'active' : ''}`}
              onClick={() => setCurrentProject('project1')}
            >
              <Key size={16} /> Project 1: CryptoVault
            </button>
            <button
              className={`nav-btn p2 ${currentProject === 'project2' ? 'active' : ''}`}
              onClick={() => setCurrentProject('project2')}
            >
              <Shield size={16} /> Project 2: SecureTunnel
            </button>
            <button
              className={`nav-btn p3 ${currentProject === 'project3' ? 'active' : ''}`}
              onClick={() => setCurrentProject('project3')}
            >
              <Activity size={16} /> Project 3: Sentinel
            </button>
          </nav>

          {/* Backend Health Status Indicators */}
          <div className="status-pill-group">
            <div className="status-indicator" title="Project 1 Backend (Port 5001)">
              <span className={`status-dot ${p1Online ? 'online' : 'offline'}`} />
              <span>P1: 5001</span>
            </div>
            <div className="status-indicator" title="Project 2 Backend (Port 5002)">
              <span className={`status-dot ${p2Online ? 'online' : 'offline'}`} />
              <span>P2: 5002</span>
            </div>
            <div className="status-indicator" title="Project 3 Backend (Port 5003)">
              <span className={`status-dot ${p3Online ? 'online' : 'offline'}`} />
              <span>P3: 5003</span>
            </div>
            <button 
              onClick={checkHealth}
              title="Refresh Service Status"
              style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 4 }}
            >
              <RefreshCw size={13} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="main-content">
        {currentProject === 'overview' && (
          <Overview 
            onSelectProject={setCurrentProject}
            p1Status={p1Online}
            p2Status={p2Online}
            p3Status={p3Online}
          />
        )}
        {currentProject === 'project1' && <Project1CryptoVault />}
        {currentProject === 'project2' && <Project2SecureTunnel />}
        {currentProject === 'project3' && <Project3Sentinel />}
      </main>
    </div>
  );
}

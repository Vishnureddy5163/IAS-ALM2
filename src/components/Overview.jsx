import React from 'react';
import { Shield, Key, Lock, Terminal, Activity, ArrowRight, Layers, FileCheck, Server, AlertTriangle } from 'lucide-react';

export default function Overview({ onSelectProject, p1Status, p2Status, p3Status }) {
  return (
    <div>
      {/* Hero Banner */}
      <div className="card" style={{ background: 'linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%)', border: '1px solid #3730a3' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <span className="badge badge-purple" style={{ marginBottom: '0.5rem' }}>KL University • KLH ALM-2</span>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc', marginBottom: '0.4rem' }}>
              Active Learning Management Project - 2
            </h1>
            <p style={{ color: '#c7d2fe', fontSize: '0.95rem', maxWidth: '780px' }}>
              Comprehensive CyberSecurity & Cryptographic Computing Suite uniting three core modules: 
              <strong> Public-Key Cryptography (CryptoVault)</strong>, 
              <strong> Transport Layer Security (SecureTunnel)</strong>, and 
              <strong> Firewall & Intrusion Detection (Sentinel)</strong>.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => onSelectProject('project1')}>
              <Key size={16} /> Open Project 1
            </button>
            <button className="btn btn-purple" onClick={() => onSelectProject('project2')}>
              <Shield size={16} /> Open Project 2
            </button>
            <button className="btn btn-danger" onClick={() => onSelectProject('project3')}>
              <Activity size={16} /> Open Project 3
            </button>
          </div>
        </div>
      </div>

      {/* 3 Project Overview Cards */}
      <div className="grid-3">
        {/* Project 1 */}
        <div className="card" style={{ borderColor: '#0284c7' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div style={{ background: 'rgba(14, 165, 233, 0.15)', padding: '0.6rem', borderRadius: '8px', color: '#38bdf8' }}>
              <Key size={24} />
            </div>
            <span className={`badge ${p1Status ? 'badge-green' : 'badge-red'}`}>
              {p1Status ? 'Port 5001 Online' : 'Port 5001 Offline'}
            </span>
          </div>
          <h2 className="card-title">Project 1: CryptoVault</h2>
          <p className="card-sub">Public-Key Cryptography & Digital Signature Toolkit</p>
          
          <ul style={{ listStyle: 'none', fontSize: '0.82rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '1.25rem' }}>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <FileCheck size={14} color="#38bdf8" /> User Authentication & X.509 CA Certificates
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Lock size={14} color="#38bdf8" /> RSA Encryption, Decryption, Sign & Verify
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Layers size={14} color="#38bdf8" /> Diffie-Hellman Alice/Bob Visualizer
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Activity size={14} color="#38bdf8" /> Elgamal Digital Signature & SHA-512
            </li>
          </ul>

          <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => onSelectProject('project1')}>
            Launch CryptoVault <ArrowRight size={15} />
          </button>
        </div>

        {/* Project 2 */}
        <div className="card" style={{ borderColor: '#7c3aed' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div style={{ background: 'rgba(139, 92, 246, 0.15)', padding: '0.6rem', borderRadius: '8px', color: '#a78bfa' }}>
              <Shield size={24} />
            </div>
            <span className={`badge ${p2Status ? 'badge-green' : 'badge-red'}`}>
              {p2Status ? 'Port 5002 Online' : 'Port 5002 Offline'}
            </span>
          </div>
          <h2 className="card-title">Project 2: SecureTunnel</h2>
          <p className="card-sub">TLS / SSH Handshake & IPsec Protocol Visualizer</p>
          
          <ul style={{ listStyle: 'none', fontSize: '0.82rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '1.25rem' }}>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Server size={14} color="#a78bfa" /> Step-by-Step TLS Handshake (Steps 1-5)
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Key size={14} color="#a78bfa" /> PRF Session Key Derivation & AES Tunnel
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Terminal size={14} color="#a78bfa" /> SSH Handshake & Diffie-Hellman Key Exchange
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Layers size={14} color="#a78bfa" /> IPsec ESP Transport vs Tunnel Mode
            </li>
          </ul>

          <button className="btn btn-purple" style={{ width: '100%' }} onClick={() => onSelectProject('project2')}>
            Launch SecureTunnel <ArrowRight size={15} />
          </button>
        </div>

        {/* Project 3 */}
        <div className="card" style={{ borderColor: '#dc2626' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', padding: '0.6rem', borderRadius: '8px', color: '#f87171' }}>
              <Activity size={24} />
            </div>
            <span className={`badge ${p3Status ? 'badge-green' : 'badge-red'}`}>
              {p3Status ? 'Port 5003 Online' : 'Port 5003 Offline'}
            </span>
          </div>
          <h2 className="card-title">Project 3: Sentinel</h2>
          <p className="card-sub">Intrusion Detection System & Firewall Simulator</p>
          
          <ul style={{ listStyle: 'none', fontSize: '0.82rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.4rem', marginBottom: '1.25rem' }}>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Shield size={14} color="#f87171" /> Firewall Rule Manager & Bastion Host Config
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Activity size={14} color="#f87171" /> Rule-Based IDS (SSH brute force, Telnet, Scan)
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <AlertTriangle size={14} color="#f87171" /> Statistical Anomaly IDS (3-Sigma Deviations)
            </li>
            <li style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <FileCheck size={14} color="#f87171" /> Threat Encyclopedia (Viruses, Worms, Defense)
            </li>
          </ul>

          <button className="btn btn-danger" style={{ width: '100%' }} onClick={() => onSelectProject('project3')}>
            Launch Sentinel <ArrowRight size={15} />
          </button>
        </div>
      </div>

      {/* Architecture & Live Environment Details */}
      <div className="card">
        <h3 className="card-title">
          <Server size={18} color="#38bdf8" /> Unified Workspace & Architectural Layout
        </h3>
        <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '1rem' }}>
          All 3 projects are organized in dedicated folders (<code>ALM2-K/Project1</code>, <code>ALM2-K/Project2</code>, <code>ALM2-K/Project3</code>) 
          and united through this master interface. You can switch between any project instantly using the top navigation buttons.
        </p>

        <div className="grid-3" style={{ fontSize: '0.8rem' }}>
          <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <strong style={{ color: '#38bdf8' }}>Project 1: CryptoVault (Port 5001)</strong>
            <p style={{ color: '#64748b', marginTop: '0.3rem' }}>
              Endpoints for PKI, RSA-OAEP / RSA-PSS, Diffie-Hellman modular exponentiation, and Elgamal/SHA-512 with SQLite storage.
            </p>
          </div>
          <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <strong style={{ color: '#a78bfa' }}>Project 2: SecureTunnel (Port 5002)</strong>
            <p style={{ color: '#64748b', marginTop: '0.3rem' }}>
              Stateful TLS/SSL and SSH handshake machines, PRF key expansion, session encryption, and IPsec ESP mode simulation.
            </p>
          </div>
          <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <strong style={{ color: '#f87171' }}>Project 3: Sentinel (Port 5003)</strong>
            <p style={{ color: '#64748b', marginTop: '0.3rem' }}>
              Packet filtering engine, Bastion Host, traffic generator, live alert dispatcher, pandas/numpy 3-sigma anomaly detector.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

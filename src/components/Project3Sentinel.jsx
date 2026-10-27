import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, FileText, Plus, Trash2, Play, RefreshCw, Server, CheckCircle2, XCircle, Search } from 'lucide-react';

const API_BASE = 'http://localhost:5003';

export default function Project3Sentinel() {
  const [activeTab, setActiveTab] = useState('firewall'); // firewall, ids, threats

  // ---------------- Firewall State ----------------
  const [rules, setRules] = useState([]);
  const [bastion, setBastion] = useState(null);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleSrc, setNewRuleSrc] = useState('ANY');
  const [newRuleDst, setNewRuleDst] = useState('ANY');
  const [newRulePort, setNewRulePort] = useState('');
  const [newRuleProto, setNewRuleProto] = useState('TCP');
  const [newRuleAction, setNewRuleAction] = useState('BLOCK');
  const [newRulePriority, setNewRulePriority] = useState(50);
  const [isBastionRule, setIsBastionRule] = useState(false);

  // Packet Inspector Form
  const [inspectSrc, setInspectSrc] = useState('198.51.100.44');
  const [inspectDst, setInspectDst] = useState('10.0.0.5');
  const [inspectPort, setInspectPort] = useState(22);
  const [inspectProto, setInspectProto] = useState('TCP');
  const [inspectResult, setInspectResult] = useState(null);

  // ---------------- IDS State ----------------
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [lastScenarioResult, setLastScenarioResult] = useState(null);

  // ---------------- Threat Encyclopedia State ----------------
  const [threats, setThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [filterCategory, setFilterCategory] = useState('ALL');

  useEffect(() => {
    fetchRules();
    fetchAlerts();
    fetchMetrics();
    fetchThreats();
  }, []);

  // ---------------- Firewall API Handlers ----------------
  const fetchRules = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/firewall/rules`);
      if (res.ok) {
        const data = await res.json();
        setRules(data.rules || []);
        setBastion(data.bastion || null);
      }
    } catch (e) {
      console.warn('Firewall rules fetch failed', e);
    }
  };

  const handleAddRule = async (e) => {
    e.preventDefault();
    if (!newRuleName) return alert('Rule name required');
    try {
      const res = await fetch(`${API_BASE}/api/firewall/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newRuleName,
          source_ip: newRuleSrc,
          dest_ip: newRuleDst,
          port: newRulePort ? parseInt(newRulePort) : null,
          protocol: newRuleProto,
          action: newRuleAction,
          priority: parseInt(newRulePriority),
          is_bastion_rule: isBastionRule ? 1 : 0
        })
      });
      if (res.ok) {
        setNewRuleName('');
        setNewRulePort('');
        fetchRules();
      }
    } catch (e) {
      alert(e.message);
    }
  };

  const handleDeleteRule = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/api/firewall/rules/${id}`, { method: 'DELETE' });
      if (res.ok) fetchRules();
    } catch (e) {
      alert(e.message);
    }
  };

  const handleInspectPacket = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/firewall/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_ip: inspectSrc,
          dest_ip: inspectDst,
          port: parseInt(inspectPort),
          protocol: inspectProto
        })
      });
      const data = await res.json();
      setInspectResult(data);
    } catch (e) {
      alert(e.message);
    }
  };

  // ---------------- IDS API Handlers ----------------
  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/ids/alerts`);
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (e) {
      console.warn('Alerts fetch failed', e);
    }
  };

  const clearAlerts = async () => {
    try {
      await fetch(`${API_BASE}/api/ids/alerts`, { method: 'DELETE' });
      setAlerts([]);
    } catch (e) {
      alert(e.message);
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/ids/metrics`);
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (e) {
      console.warn('Metrics fetch failed', e);
    }
  };

  const triggerTrafficScenario = async (scenario) => {
    setTrafficLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/ids/traffic/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      const data = await res.json();
      setLastScenarioResult(data);
      fetchAlerts();
      fetchMetrics();
    } catch (e) {
      alert(e.message);
    } finally {
      setTrafficLoading(false);
    }
  };

  // ---------------- Threats API Handlers ----------------
  const fetchThreats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/threats`);
      if (res.ok) {
        const data = await res.json();
        setThreats(data.threats || []);
        if (data.threats?.length > 0) setSelectedThreat(data.threats[0]);
      }
    } catch (e) {
      console.warn('Threats fetch failed', e);
    }
  };

  const filteredThreats = filterCategory === 'ALL'
    ? threats
    : threats.filter(t => t.category.toUpperCase() === filterCategory);

  return (
    <div>
      {/* Module Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#f87171', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={22} /> Project 3: "Sentinel"
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
            An Intrusion Detection & Firewall Simulator (Rule-Based IDS, Statistical Anomaly IDS, Bastion Host, Threat Encyclopedia)
          </p>
        </div>
        <span className="badge badge-red">Backend: Port 5003</span>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="sub-nav">
        <button className={`sub-nav-btn ${activeTab === 'firewall' ? 'active' : ''}`} onClick={() => setActiveTab('firewall')}>
          <Shield size={15} /> 1. Firewall Rule Manager & Bastion Host
        </button>
        <button className={`sub-nav-btn ${activeTab === 'ids' ? 'active' : ''}`} onClick={() => setActiveTab('ids')}>
          <Activity size={15} /> 2. IDS Engine & Anomaly Dashboard
        </button>
        <button className={`sub-nav-btn ${activeTab === 'threats' ? 'active' : ''}`} onClick={() => setActiveTab('threats')}>
          <FileText size={15} /> 3. Threat Encyclopedia
        </button>
      </div>

      {/* ---------------- 1. FIREWALL RULE MANAGER ---------------- */}
      {activeTab === 'firewall' && (
        <div>
          {/* Bastion Host Configuration Header */}
          {bastion && (
            <div className="card" style={{ background: '#090d16', border: '1px solid #1e293b', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Server size={18} color="#38bdf8" />
                  <div>
                    <strong style={{ color: '#f8fafc', fontSize: '0.95rem' }}>Designated Bastion Host:</strong>{' '}
                    <span style={{ color: '#38bdf8' }}>{bastion.name} ({bastion.ip})</span>
                  </div>
                </div>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                  Allowed Admin Subnet: <code>{bastion.allowed_management_subnet}</code> • Monitored Ports: <code>{bastion.monitored_ports.join(', ')}</code>
                </div>
              </div>
            </div>
          )}

          {/* Rules Table & Add Rule Form */}
          <div className="card">
            <h3 className="card-title"><Shield size={18} color="#f87171" /> Configured Firewall Rules</h3>
            <p className="card-sub">
              Packet processing engine matches incoming packets top-down by priority (lowest number = highest priority). First match dictates action.
            </p>

            <div style={{ overflowX: 'auto', marginBottom: '1.5rem' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Pri</th>
                    <th>Name</th>
                    <th>Direction</th>
                    <th>Source IP</th>
                    <th>Dest IP</th>
                    <th>Proto</th>
                    <th>Port</th>
                    <th>Action</th>
                    <th>Type</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {rules.map(r => (
                    <tr key={r.id}>
                      <td><span className="badge badge-purple">{r.priority}</span></td>
                      <td><strong>{r.name}</strong></td>
                      <td>{r.direction}</td>
                      <td><code>{r.source_ip}</code></td>
                      <td><code>{r.dest_ip}</code></td>
                      <td>{r.protocol}</td>
                      <td>{r.port !== null ? r.port : 'ANY'}</td>
                      <td>
                        <span className={`badge ${r.action === 'ALLOW' ? 'badge-green' : 'badge-red'}`}>
                          {r.action}
                        </span>
                      </td>
                      <td>
                        {r.is_bastion_rule ? (
                          <span className="badge badge-blue">Bastion</span>
                        ) : (
                          <span style={{ color: '#64748b', fontSize: '0.75rem' }}>Standard</span>
                        )}
                      </td>
                      <td>
                        <button 
                          style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer' }}
                          onClick={() => handleDeleteRule(r.id)}
                          title="Delete Rule"
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Add Rule Form */}
            <form onSubmit={handleAddRule} style={{ background: '#090d16', padding: '1rem', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <h4 style={{ fontSize: '0.85rem', color: '#f1f5f9', marginBottom: '0.75rem', fontWeight: 600 }}>
                <Plus size={14} style={{ display: 'inline', marginRight: 4 }} /> Add New Firewall Rule
              </h4>
              <div className="grid-4" style={{ marginBottom: '0.75rem' }}>
                <div>
                  <label className="form-label">Rule Name</label>
                  <input className="form-input" placeholder="e.g. Block Port 23" value={newRuleName} onChange={e => setNewRuleName(e.target.value)} />
                </div>
                <div>
                  <label className="form-label">Source IP / CIDR</label>
                  <input className="form-input" placeholder="ANY or 192.168.1.100" value={newRuleSrc} onChange={e => setNewRuleSrc(e.target.value)} />
                </div>
                <div>
                  <label className="form-label">Destination IP</label>
                  <input className="form-input" placeholder="ANY or 10.0.0.5" value={newRuleDst} onChange={e => setNewRuleDst(e.target.value)} />
                </div>
                <div>
                  <label className="form-label">Protocol</label>
                  <select className="form-select" value={newRuleProto} onChange={e => setNewRuleProto(e.target.value)}>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="ANY">ANY</option>
                  </select>
                </div>
              </div>
              <div className="grid-4" style={{ alignItems: 'flex-end' }}>
                <div>
                  <label className="form-label">Port</label>
                  <input className="form-input" placeholder="80, 22, 23 (blank for ANY)" value={newRulePort} onChange={e => setNewRulePort(e.target.value)} />
                </div>
                <div>
                  <label className="form-label">Action</label>
                  <select className="form-select" value={newRuleAction} onChange={e => setNewRuleAction(e.target.value)}>
                    <option value="BLOCK">BLOCK (Drop)</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>
                <div>
                  <label className="form-label">Priority (Lower = First)</label>
                  <input className="form-input" type="number" value={newRulePriority} onChange={e => setNewRulePriority(e.target.value)} />
                </div>
                <div>
                  <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
                    <Plus size={14} /> Add Rule
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Live Packet Processing Engine Tester */}
          <div className="card">
            <h3 className="card-title"><Search size={18} color="#38bdf8" /> Live Packet Inspection Engine</h3>
            <p className="card-sub">Simulate an incoming packet and verify how the firewall rule set evaluates it.</p>

            <div className="grid-4" style={{ marginBottom: '1rem' }}>
              <div>
                <label className="form-label">Packet Source IP</label>
                <input className="form-input" value={inspectSrc} onChange={e => setInspectSrc(e.target.value)} />
              </div>
              <div>
                <label className="form-label">Packet Dest IP</label>
                <input className="form-input" value={inspectDst} onChange={e => setInspectDst(e.target.value)} />
              </div>
              <div>
                <label className="form-label">Target Port</label>
                <input className="form-input" type="number" value={inspectPort} onChange={e => setInspectPort(e.target.value)} />
              </div>
              <div>
                <label className="form-label">Protocol</label>
                <select className="form-select" value={inspectProto} onChange={e => setInspectProto(e.target.value)}>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                </select>
              </div>
            </div>

            <button className="btn btn-primary" onClick={handleInspectPacket}>
              <Play size={14} /> Inspect Packet
            </button>

            {inspectResult && (
              <div style={{ marginTop: '1rem', padding: '0.85rem', borderRadius: '6px', background: inspectResult.decision === 'ALLOW' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)', border: `1px solid ${inspectResult.decision === 'ALLOW' ? '#059669' : '#dc2626'}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, fontSize: '0.95rem', color: inspectResult.decision === 'ALLOW' ? '#34d399' : '#f87171' }}>
                  {inspectResult.decision === 'ALLOW' ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
                  Packet Evaluation Result: {inspectResult.decision}
                </div>
                <div style={{ fontSize: '0.82rem', color: '#e2e8f0', marginTop: '0.3rem' }}>
                  <strong>Policy Rationale:</strong> {inspectResult.reason}
                </div>
                {inspectResult.is_bastion_targeted && (
                  <div style={{ fontSize: '0.8rem', color: '#38bdf8', marginTop: '0.2rem' }}>
                    Notice: Target is the Bastion Host ({bastion?.ip}). Enhanced perimeter audit logging triggered.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ---------------- 2. IDS ENGINE & ANOMALY DASHBOARD ---------------- */}
      {activeTab === 'ids' && (
        <div>
          {/* Traffic Generator Controls */}
          <div className="card">
            <h3 className="card-title"><Activity size={18} color="#f87171" /> Network Traffic Generator</h3>
            <p className="card-sub">
              Inject synthetic traffic vectors into the simulated network to test Rule-Based alerts and Statistical Anomaly detection.
            </p>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button className="btn btn-secondary" onClick={() => triggerTrafficScenario('normal')} disabled={trafficLoading}>
                Normal HTTP/HTTPS
              </button>
              <button className="btn btn-primary" onClick={() => triggerTrafficScenario('ssh_bruteforce')} disabled={trafficLoading}>
                SSH Brute Force (5+ attempts)
              </button>
              <button className="btn btn-purple" onClick={() => triggerTrafficScenario('telnet_insecure')} disabled={trafficLoading}>
                Port 23 Telnet Scan
              </button>
              <button className="btn btn-secondary" style={{ borderColor: '#ca8a04', color: '#fef08a' }} onClick={() => triggerTrafficScenario('port_scan')} disabled={trafficLoading}>
                Reconnaissance Port Scan
              </button>
              <button className="btn btn-danger" onClick={() => triggerTrafficScenario('syn_flood')} disabled={trafficLoading}>
                <AlertTriangle size={14} /> Volumetric SYN Flood (Anomaly)
              </button>
            </div>
          </div>

          {/* Statistical Anomaly Detection Metrics & Dynamic Visualizer */}
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h3 className="card-title"><AlertTriangle size={18} color="#f59e0b" /> Statistical Anomaly Detector (3-Sigma Gaussian Model)</h3>
                <p className="card-sub">
                  Calculates running baseline mean (μ) and standard deviation (σ) via NumPy/Pandas. Triggers critical anomaly alert when metric exceeds μ + 3σ.
                </p>
              </div>
              {metrics && (
                <div style={{ display: 'flex', gap: '1rem', fontSize: '0.8rem' }}>
                  <div style={{ background: '#090d16', padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <span style={{ color: '#64748b' }}>Mean (μ):</span> <strong style={{ color: '#38bdf8' }}>{metrics.current_mean} pkts/s</strong>
                  </div>
                  <div style={{ background: '#090d16', padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <span style={{ color: '#64748b' }}>Std Dev (σ):</span> <strong style={{ color: '#a78bfa' }}>{metrics.current_std}</strong>
                  </div>
                  <div style={{ background: '#090d16', padding: '0.4rem 0.75rem', borderRadius: '6px', border: '1px solid #dc2626' }}>
                    <span style={{ color: '#f87171' }}>3σ Threshold:</span> <strong style={{ color: '#f87171' }}>{metrics.threshold_3sigma} pkts/s</strong>
                  </div>
                </div>
              )}
            </div>

            {/* SVG Chart Visualization */}
            {metrics?.history && (
              <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem', position: 'relative' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.5rem' }}>
                  <span>Packet Rate History (Last {metrics.history.length} samples)</span>
                  <span style={{ color: '#ef4444' }}>--- 3-Sigma Anomaly Threshold ({metrics.threshold_3sigma})</span>
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-end', height: '140px', gap: '3px', paddingBottom: '10px', borderBottom: '1px solid #334155' }}>
                  {metrics.history.map((pt, i) => {
                    const maxH = 65; // scale factor
                    const barHeight = Math.min(130, Math.max(8, (pt.rate / maxH) * 130));
                    const isOver = pt.rate > pt.threshold;

                    return (
                      <div
                        key={i}
                        title={`Sample #${pt.index}: ${pt.rate} pkts/s ${isOver ? '[ANOMALY]' : ''}`}
                        style={{
                          flex: 1,
                          height: `${barHeight}px`,
                          background: isOver ? '#ef4444' : '#0284c7',
                          borderRadius: '2px 2px 0 0',
                          transition: 'height 0.3s ease',
                          cursor: 'pointer'
                        }}
                      />
                    );
                  })}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: '#64748b', marginTop: '0.4rem' }}>
                  <span>Earliest recorded</span>
                  <span>Latest observation</span>
                </div>
              </div>
            )}
          </div>

          {/* Real-Time IDS Alert Feed */}
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
              <h3 className="card-title">
                <AlertTriangle size={18} color="#ef4444" /> Real-Time Intrusion Alert Feed ({alerts.length})
              </h3>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-secondary" style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }} onClick={fetchAlerts}>
                  <RefreshCw size={12} /> Refresh
                </button>
                <button className="btn btn-danger" style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }} onClick={clearAlerts}>
                  <Trash2 size={12} /> Clear Alerts
                </button>
              </div>
            </div>

            <div style={{ maxHeight: '320px', overflowY: 'auto' }}>
              {alerts.length === 0 ? (
                <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b', background: '#090d16', borderRadius: '6px' }}>
                  No active alerts. Use the Traffic Generator above to inject security events.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {alerts.map(a => (
                    <div 
                      key={a.id} 
                      style={{ 
                        background: '#090d16', 
                        border: `1px solid ${a.severity === 'CRITICAL' ? '#dc2626' : a.severity === 'HIGH' ? '#ea580c' : '#334155'}`, 
                        borderRadius: '6px', 
                        padding: '0.75rem' 
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className={`badge ${a.severity === 'CRITICAL' ? 'badge-red' : a.severity === 'HIGH' ? 'badge-yellow' : 'badge-blue'}`}>
                            {a.severity}
                          </span>
                          <span className="badge badge-purple">{a.alert_type}</span>
                          <strong style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>{a.rule_name}</strong>
                        </div>
                        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>{a.timestamp}</span>
                      </div>
                      <div style={{ fontSize: '0.82rem', color: '#cbd5e1' }}>{a.message}</div>
                      {a.details && (
                        <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                          Target: {a.source_ip} -&gt; {a.dest_ip} (Port: {a.port || 'ANY'}, Proto: {a.protocol})
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ---------------- 3. THREAT ENCYCLOPEDIA ---------------- */}
      {activeTab === 'threats' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h3 className="card-title"><FileText size={18} color="#38bdf8" /> Threat Encyclopedia (Viruses, Worms & Defense)</h3>
              <p className="card-sub">Theoretical background and countermeasures for computer viruses, autonomous worms, and firewall design.</p>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              {['ALL', 'VIRUSES', 'WORMS', 'FIREWALLS'].map(cat => (
                <button
                  key={cat}
                  className={`btn ${filterCategory === cat ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem' }}
                  onClick={() => setFilterCategory(cat)}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          <div className="grid-2">
            {/* List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '420px', overflowY: 'auto' }}>
              {filteredThreats.map(t => (
                <div
                  key={t.id}
                  onClick={() => setSelectedThreat(t)}
                  style={{
                    background: selectedThreat?.id === t.id ? '#1e293b' : '#090d16',
                    border: `1px solid ${selectedThreat?.id === t.id ? '#38bdf8' : '#1e293b'}`,
                    padding: '0.75rem',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <strong style={{ fontSize: '0.85rem', color: selectedThreat?.id === t.id ? '#38bdf8' : '#f1f5f9' }}>
                      {t.title}
                    </strong>
                    <span className="badge badge-purple">{t.category}</span>
                  </div>
                  <p style={{ fontSize: '0.78rem', color: '#94a3b8' }}>{t.summary}</p>
                </div>
              ))}
            </div>

            {/* Detail View */}
            {selectedThreat && (
              <div style={{ background: '#090d16', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                <span className="badge badge-blue" style={{ marginBottom: '0.5rem' }}>{selectedThreat.category}</span>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.5rem' }}>
                  {selectedThreat.title}
                </h3>
                <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '1rem' }}>
                  {selectedThreat.summary}
                </p>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                    Infection & Propagation Mechanism:
                  </div>
                  <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.6 }}>
                    {selectedThreat.mechanism}
                  </p>
                </div>

                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.8rem', color: '#fbbf24', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                    Historical Examples:
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.3rem' }}>
                    {selectedThreat.historical_examples.map((ex, idx) => (
                      <span key={idx} className="badge badge-yellow">{ex}</span>
                    ))}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                    Technical Countermeasures:
                  </div>
                  <ul style={{ listStyle: 'disc', paddingLeft: '1.2rem', fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.3rem' }}>
                    {selectedThreat.countermeasures.map((cm, idx) => (
                      <li key={idx} style={{ marginBottom: '0.2rem' }}>{cm}</li>
                    ))}
                  </ul>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

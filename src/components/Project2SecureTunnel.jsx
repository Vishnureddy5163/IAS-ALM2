import React, { useState, useEffect } from 'react';
import { Shield, Server, Terminal, Layers, ArrowRight, CheckCircle2, Lock, Key, RefreshCw, Send, Radio } from 'lucide-react';

const API_BASE = 'http://localhost:5002';

export default function Project2SecureTunnel() {
  const [activeTab, setActiveTab] = useState('tls'); // tls, ssh, ipsec

  // ---------------- TLS State ----------------
  const [tlsSessionId, setTlsSessionId] = useState(null);
  const [tlsStep, setTlsStep] = useState(0);
  const [tlsHistory, setTlsHistory] = useState([]);
  const [tlsCipher, setTlsCipher] = useState('TLS_AES_128_GCM_SHA256');
  const [tlsMsg, setTlsMsg] = useState('GET /finance/transfers HTTP/1.1');
  const [tlsEncryptedRes, setTlsEncryptedRes] = useState(null);
  const [tlsLoading, setTlsLoading] = useState(false);

  // ---------------- SSH State ----------------
  const [sshSessionId, setSshSessionId] = useState(null);
  const [sshStep, setSshStep] = useState(0);
  const [sshHistory, setSshHistory] = useState([]);
  const [sshUsername, setSshUsername] = useState('admin_dev');
  const [sshLoading, setSshLoading] = useState(false);

  // ---------------- IPsec State ----------------
  const [ipsecMode, setIpsecMode] = useState('transport'); // transport or tunnel
  const [ipsecSrc, setIpsecSrc] = useState('192.168.1.105');
  const [ipsecDst, setIpsecDst] = useState('203.0.113.50');
  const [ipsecGatewaySrc, setIpsecGatewaySrc] = useState('198.51.100.1');
  const [ipsecGatewayDst, setIpsecGatewayDst] = useState('203.0.113.1');
  const [ipsecPayload, setIpsecPayload] = useState('CONFIDENTIAL_TRANSACTION_PAYLOAD');
  const [ipsecProtocol, setIpsecProtocol] = useState('TCP');
  const [ipsecAnalysis, setIpsecAnalysis] = useState(null);

  useEffect(() => {
    initTlsSession();
    initSshSession();
    fetchIpsecAnalysis('transport');
  }, []);

  // ---------------- TLS Handlers ----------------
  const initTlsSession = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/tls/init`, { method: 'POST' });
      const data = await res.json();
      setTlsSessionId(data.session_id);
      setTlsStep(0);
      setTlsHistory([]);
      setTlsEncryptedRes(null);
    } catch (e) {
      console.warn('TLS backend error', e);
    }
  };

  const advanceTlsStep = async () => {
    if (!tlsSessionId || tlsStep >= 5) return;
    setTlsLoading(true);
    const nextStep = tlsStep + 1;
    try {
      const res = await fetch(`${API_BASE}/api/tls/step/${nextStep}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: tlsSessionId,
          cipher_suite: tlsCipher
        })
      });
      const data = await res.json();
      if (res.ok) {
        setTlsStep(nextStep);
        setTlsHistory(prev => [...prev, data]);
      } else {
        alert(data.error);
      }
    } catch (e) {
      alert(e.message);
    } finally {
      setTlsLoading(false);
    }
  };

  const handleTlsSendData = async () => {
    if (!tlsSessionId || tlsStep < 5) return;
    try {
      const res = await fetch(`${API_BASE}/api/tls/send-data`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: tlsSessionId, message: tlsMsg })
      });
      const data = await res.json();
      setTlsEncryptedRes(data);
    } catch (e) {
      alert(e.message);
    }
  };

  // ---------------- SSH Handlers ----------------
  const initSshSession = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/ssh/init`, { method: 'POST' });
      const data = await res.json();
      setSshSessionId(data.session_id);
      setSshStep(0);
      setSshHistory([]);
    } catch (e) {
      console.warn('SSH backend error', e);
    }
  };

  const advanceSshStep = async () => {
    if (!sshSessionId || sshStep >= 5) return;
    setSshLoading(true);
    const nextStep = sshStep + 1;
    try {
      const res = await fetch(`${API_BASE}/api/ssh/step/${nextStep}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sshSessionId, username: sshUsername })
      });
      const data = await res.json();
      if (res.ok) {
        setSshStep(nextStep);
        setSshHistory(prev => [...prev, data]);
      } else {
        alert(data.error);
      }
    } catch (e) {
      alert(e.message);
    } finally {
      setSshLoading(false);
    }
  };

  // ---------------- IPsec Handlers ----------------
  const fetchIpsecAnalysis = async (mode = ipsecMode) => {
    try {
      const res = await fetch(`${API_BASE}/api/ipsec/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          src_ip: ipsecSrc,
          dst_ip: ipsecDst,
          gateway_src: ipsecGatewaySrc,
          gateway_dst: ipsecGatewayDst,
          protocol: ipsecProtocol,
          payload: ipsecPayload
        })
      });
      const data = await res.json();
      setIpsecAnalysis(data);
    } catch (e) {
      console.warn('IPsec backend error', e);
    }
  };

  const toggleIpsecMode = (mode) => {
    setIpsecMode(mode);
    fetchIpsecAnalysis(mode);
  };

  return (
    <div>
      {/* Module Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#a78bfa', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={22} /> Project 2: "SecureTunnel"
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
            Transport Layer Security (TLS/SSH) & IPsec Packet Encapsulation Visualizer
          </p>
        </div>
        <span className="badge badge-purple">Backend: Port 5002</span>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="sub-nav">
        <button className={`sub-nav-btn ${activeTab === 'tls' ? 'active' : ''}`} onClick={() => setActiveTab('tls')}>
          <Server size={15} /> 1. TLS/SSL Handshake Simulator
        </button>
        <button className={`sub-nav-btn ${activeTab === 'ssh' ? 'active' : ''}`} onClick={() => setActiveTab('ssh')}>
          <Terminal size={15} /> 2. SSH Connection Simulator
        </button>
        <button className={`sub-nav-btn ${activeTab === 'ipsec' ? 'active' : ''}`} onClick={() => setActiveTab('ipsec')}>
          <Layers size={15} /> 3. IPsec (ESP) Packet Visualizer
        </button>
      </div>

      {/* ---------------- 1. TLS HANDSHAKE ---------------- */}
      {activeTab === 'tls' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
            <div>
              <h3 className="card-title"><Server size={18} color="#a78bfa" /> TLS 1.2 / 1.3 Step-by-Step Handshake</h3>
              <p className="card-sub">
                Visualizes symmetric session key distribution using asymmetric RSA encryption and PRF key derivation.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <span className="badge badge-blue">Session: {tlsSessionId || 'Init'}</span>
              <button className="btn btn-secondary" style={{ padding: '0.4rem 0.75rem' }} onClick={initTlsSession}>
                <RefreshCw size={13} /> Reset
              </button>
              <button 
                className="btn btn-purple" 
                onClick={advanceTlsStep} 
                disabled={tlsStep >= 5 || tlsLoading}
              >
                {tlsStep === 0 ? 'Start Handshake' : tlsStep < 5 ? `Advance to Step ${tlsStep + 1}` : 'Handshake Complete'}
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* Dual Panel: Client vs Server Status */}
          <div className="grid-2" style={{ marginBottom: '1.25rem' }}>
            <div style={{ background: '#090d16', border: '1px solid #1e293b', padding: '1rem', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <strong style={{ color: '#38bdf8' }}>Client (Web Browser)</strong>
                <span className="badge badge-blue">State: {tlsStep >= 5 ? 'Encrypted Tunnel Active' : `Negotiating (Step ${tlsStep})`}</span>
              </div>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                Initiates connection, presents supported cipher suites, verifies server identity via X.509 cert, generates and encrypts pre-master secret.
              </p>
            </div>

            <div style={{ background: '#090d16', border: '1px solid #1e293b', padding: '1rem', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <strong style={{ color: '#a78bfa' }}>Server (securetunnel.local)</strong>
                <span className="badge badge-purple">Port: 443 (HTTPS)</span>
              </div>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                Selects cipher suite, transmits digital certificate, decrypts pre-master secret with RSA private key, derives symmetric session keys.
              </p>
            </div>
          </div>

          {/* Handshake Step Cards */}
          <div className="handshake-timeline">
            {[
              { num: 1, title: 'Step 1: Client Hello', desc: 'Client sends client_random and list of supported cipher suites.' },
              { num: 2, title: 'Step 2: Server Hello & Certificate', desc: 'Server selects cipher suite, sends server_random and X.509 certificate.' },
              { num: 3, title: 'Step 3: Client Key Exchange', desc: 'Client verifies cert, generates 48-byte pre-master secret, encrypts with server RSA public key.' },
              { num: 4, title: 'Step 4: Session Key Generation', desc: 'Both independently compute Master Secret via PRF and derive 4 symmetric keys.' },
              { num: 5, title: 'Step 5: Finished & Verified', desc: 'Both exchange encrypted Finished messages; secure tunnel ready for AES data transmission.' }
            ].map(s => {
              const item = tlsHistory.find(h => h.step === s.num);
              const isCurrent = tlsStep === s.num;
              const isPast = tlsStep > s.num;

              return (
                <div key={s.num} className={`step-card ${isCurrent ? 'active' : ''} ${isPast ? 'completed' : ''}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                    <h4 style={{ fontSize: '0.92rem', color: isPast ? '#34d399' : isCurrent ? '#38bdf8' : '#64748b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {isPast ? <CheckCircle2 size={16} color="#34d399" /> : <span style={{ width: 16, height: 16, borderRadius: '50%', background: isCurrent ? '#38bdf8' : '#334155', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.65rem', color: '#000', fontWeight: 800 }}>{s.num}</span>}
                      {s.title}
                    </h4>
                    {item && <span className="badge badge-purple">{item.direction}</span>}
                  </div>
                  <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{s.desc}</p>

                  {item && (
                    <div style={{ marginTop: '0.6rem', padding: '0.6rem', background: '#090d16', borderRadius: '6px', fontSize: '0.78rem', border: '1px solid #1e293b' }}>
                      <div style={{ color: '#e2e8f0', marginBottom: '0.2rem' }}><strong>Detail:</strong> {item.explanation}</div>
                      {item.details?.server_certificate_pem && (
                        <div style={{ color: '#a5f3fc', marginTop: '0.3rem' }}>
                          Certificate transmitted: <code>CN=securetunnel.local (RSA-2048)</code>
                        </div>
                      )}
                      {item.details?.derived_keys && (
                        <div style={{ marginTop: '0.3rem', color: '#34d399' }}>
                          <div><strong>Client Write Key:</strong> <code>{item.details.derived_keys.client_write_key}</code></div>
                          <div><strong>Server Write Key:</strong> <code>{item.details.derived_keys.server_write_key}</code></div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Symmetric Transmission Section (Active when Step 5 reached) */}
          {tlsStep === 5 && (
            <div style={{ marginTop: '1.5rem', padding: '1.25rem', background: 'rgba(16, 185, 129, 0.08)', border: '1px solid #059669', borderRadius: '8px' }}>
              <h4 style={{ color: '#34d399', fontWeight: 700, marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Lock size={16} /> Transmit Application Data over Secure TLS Tunnel
              </h4>
              <p style={{ fontSize: '0.8rem', color: '#a7f3d0', marginBottom: '0.75rem' }}>
                Payload will be symmetrically encrypted with the derived <code>client_write_key</code> using AES-128-GCM authenticated cipher.
              </p>

              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input className="form-input" value={tlsMsg} onChange={e => setTlsMsg(e.target.value)} />
                <button className="btn btn-success" onClick={handleTlsSendData}>
                  <Send size={14} /> Send Encrypted
                </button>
              </div>

              {tlsEncryptedRes && (
                <div style={{ marginTop: '1rem', background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '0.82rem' }}>
                  <div style={{ color: '#38bdf8' }}><strong>Ciphertext (Hex):</strong> {tlsEncryptedRes.symmetric_ciphertext_hex}</div>
                  <div style={{ color: '#a78bfa', marginTop: '0.2rem' }}><strong>Auth Tag (MAC):</strong> {tlsEncryptedRes.authentication_tag_hex}</div>
                  <div style={{ color: '#64748b', marginTop: '0.2rem' }}>Cipher: {tlsEncryptedRes.cipher} • Status: {tlsEncryptedRes.status}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ---------------- 2. SSH HANDSHAKE ---------------- */}
      {activeTab === 'ssh' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
            <div>
              <h3 className="card-title"><Terminal size={18} color="#a78bfa" /> Simplified SSH Connection Simulation</h3>
              <p className="card-sub">
                Demonstrates Version Exchange, Diffie-Hellman Key Exchange, Server Host Key Authentication, and PTY Shell Session.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button className="btn btn-secondary" style={{ padding: '0.4rem 0.75rem' }} onClick={initSshSession}>
                <RefreshCw size={13} /> Reset
              </button>
              <button className="btn btn-purple" onClick={advanceSshStep} disabled={sshStep >= 5 || sshLoading}>
                {sshStep === 0 ? 'Start SSH Connection' : sshStep < 5 ? `Advance to Step ${sshStep + 1}` : 'SSH Connected'}
                <ArrowRight size={14} />
              </button>
            </div>
          </div>

          {/* SSH Steps */}
          <div className="handshake-timeline">
            {[
              { num: 1, title: 'Step 1: Protocol Version Exchange', desc: 'Client and Server exchange identification strings (e.g., SSH-2.0-OpenSSH_8.9 vs OpenSSH_9.0).' },
              { num: 2, title: 'Step 2: Key Exchange (Diffie-Hellman)', desc: 'Client sends exchange value e. Server replies with f and computes shared secret K.' },
              { num: 3, title: 'Step 3: Server Authentication', desc: 'Server sends public host key and signs exchange hash H with private host key.' },
              { num: 4, title: 'Step 4: User Authentication', desc: 'Client submits credentials (password or SSH public key auth).' },
              { num: 5, title: 'Step 5: Secure Channel & Shell Established', desc: 'Encrypted PTY pseudo-terminal session opened with derived session key.' }
            ].map(s => {
              const item = sshHistory.find(h => h.step === s.num);
              const isCurrent = sshStep === s.num;
              const isPast = sshStep > s.num;

              return (
                <div key={s.num} className={`step-card ${isCurrent ? 'active' : ''} ${isPast ? 'completed' : ''}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                    <h4 style={{ fontSize: '0.92rem', color: isPast ? '#34d399' : isCurrent ? '#a78bfa' : '#64748b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {isPast ? <CheckCircle2 size={16} color="#34d399" /> : <span style={{ width: 16, height: 16, borderRadius: '50%', background: isCurrent ? '#a78bfa' : '#334155', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.65rem', color: '#000', fontWeight: 800 }}>{s.num}</span>}
                      {s.title}
                    </h4>
                  </div>
                  <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{s.desc}</p>

                  {item && (
                    <div style={{ marginTop: '0.6rem', padding: '0.6rem', background: '#090d16', borderRadius: '6px', fontSize: '0.78rem', border: '1px solid #1e293b' }}>
                      <div style={{ color: '#e2e8f0' }}>{item.explanation}</div>
                      {item.server_host_key_fingerprint && (
                        <div style={{ color: '#fbbf24', marginTop: '0.2rem' }}>
                          Host Key Fingerprint: <code>{item.server_host_key_fingerprint}</code>
                        </div>
                      )}
                      {item.active_session && (
                        <div style={{ marginTop: '0.4rem', padding: '0.5rem', background: '#000', color: '#22c55e', fontFamily: 'monospace', borderRadius: '4px' }}>
                          <div>Last login: {new Date().toUTCString()} from 192.168.1.100</div>
                          <div>{item.active_session.prompt} uname -a</div>
                          <div>Linux securetunnel 5.15.0-generic #1 SMP x86_64 GNU/Linux</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ---------------- 3. IPSEC VISUALIZER ---------------- */}
      {activeTab === 'ipsec' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
            <div>
              <h3 className="card-title"><Layers size={18} color="#a78bfa" /> IP Security (IPsec) ESP Packet Encapsulation</h3>
              <p className="card-sub">
                Interactive packet breakdown comparing <strong>Transport Mode</strong> (host-to-host) vs <strong>Tunnel Mode</strong> (gateway-to-gateway VPN).
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem', background: '#090d16', padding: '0.25rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <button 
                className={`btn ${ipsecMode === 'transport' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ padding: '0.35rem 0.8rem', fontSize: '0.8rem' }}
                onClick={() => toggleIpsecMode('transport')}
              >
                Transport Mode
              </button>
              <button 
                className={`btn ${ipsecMode === 'tunnel' ? 'btn-purple' : 'btn-secondary'}`}
                style={{ padding: '0.35rem 0.8rem', fontSize: '0.8rem' }}
                onClick={() => toggleIpsecMode('tunnel')}
              >
                Tunnel Mode (VPN)
              </button>
            </div>
          </div>

          {/* Mode Description Banner */}
          {ipsecAnalysis && (
            <div style={{ padding: '0.75rem 1rem', background: '#090d16', border: '1px solid #1e293b', borderRadius: '6px', fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '1.25rem' }}>
              <strong style={{ color: ipsecMode === 'transport' ? '#38bdf8' : '#a78bfa' }}>
                {ipsecMode === 'transport' ? 'Transport Mode Architecture:' : 'Tunnel Mode (VPN Gateway) Architecture:'}
              </strong>
              <p style={{ marginTop: '0.25rem' }}>{ipsecAnalysis.explanation}</p>
            </div>
          )}

          {/* Color-Coded Packet Block Diagram */}
          {ipsecAnalysis?.elements && (
            <div>
              <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', marginBottom: '0.4rem', letterSpacing: '0.05em' }}>
                Encapsulated IPsec ESP Datagram Structure:
              </div>
              <div className="packet-diagram">
                {ipsecAnalysis.elements.map((el, idx) => (
                  <div key={idx} className={`packet-block ${el.color}`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <strong style={{ fontSize: '0.82rem' }}>{el.field}</strong>
                      <span className={`badge ${el.encrypted ? 'badge-green' : el.authenticated ? 'badge-yellow' : 'badge-blue'}`}>
                        {el.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', opacity: 0.9 }}>
                      {el.content}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                      {el.description}
                    </div>
                  </div>
                ))}
              </div>

              {/* Legend & Security Guarantees */}
              <div className="grid-2" style={{ marginTop: '1rem', fontSize: '0.82rem' }}>
                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                  <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '0.4rem' }}>Color Legend:</div>
                  <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <span style={{ color: '#38bdf8' }}>■ Blue: Plaintext IP Header</span>
                    <span style={{ color: '#fbbf24' }}>■ Yellow: ESP Header (Auth Only)</span>
                    <span style={{ color: '#34d399' }}>■ Green: Encrypted & Authenticated</span>
                    <span style={{ color: '#a78bfa' }}>■ Purple: ICV Auth Tag</span>
                  </div>
                </div>

                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                  <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '0.4rem' }}>Cryptographic Guarantees:</div>
                  <div style={{ color: '#cbd5e1' }}>
                    • <strong>Confidentiality:</strong> {ipsecAnalysis.security_analysis.confidentiality}<br />
                    • <strong>Integrity:</strong> {ipsecAnalysis.security_analysis.integrity}<br />
                    • <strong>Anti-Replay:</strong> {ipsecAnalysis.security_analysis.replay_protection}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

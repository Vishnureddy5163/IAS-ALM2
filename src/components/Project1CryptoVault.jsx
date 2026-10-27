import React, { useState, useEffect } from 'react';
import { Key, Lock, Unlock, FileCheck, CheckCircle2, XCircle, ArrowRight, Download, RefreshCw, Hash, Shield } from 'lucide-react';

const API_BASE = 'http://localhost:5001';

export default function Project1CryptoVault() {
  const [activeTab, setActiveTab] = useState('pki'); // pki, rsa, dh, elgamal

  // ---------------- PKI & User Auth State ----------------
  const [username, setUsername] = useState('alice_cyber');
  const [password, setPassword] = useState('SecurePass123!');
  const [currentUser, setCurrentUser] = useState(null);
  const [pkiStatus, setPkiStatus] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // ---------------- RSA Module State ----------------
  const [rsaPlaintext, setRsaPlaintext] = useState('Confidential message for KLH evaluation.');
  const [rsaCiphertext, setRsaCiphertext] = useState('');
  const [rsaDecrypted, setRsaDecrypted] = useState('');
  const [rsaSignature, setRsaSignature] = useState('');
  const [rsaVerifyResult, setRsaVerifyResult] = useState(null);
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [privateKeyPem, setPrivateKeyPem] = useState('');
  const [rsaLoading, setRsaLoading] = useState(false);

  // ---------------- Diffie-Hellman State ----------------
  const [dhPrime, setDhPrime] = useState(353);
  const [dhGen, setDhGen] = useState(3);
  const [alicePriv, setAlicePriv] = useState(97);
  const [bobPriv, setBobPriv] = useState(233);
  const [dhStep, setDhStep] = useState(1);
  const [dhResult, setDhResult] = useState(null);
  const [dhLoading, setDhLoading] = useState(false);

  // ---------------- Elgamal & SHA-512 State ----------------
  const [elgamalMsg, setElgamalMsg] = useState('Transfer $50,000 from Account A to Account B');
  const [elgamalHash, setElgamalHash] = useState('');
  const [elgamalKeys, setElgamalKeys] = useState(null);
  const [elgamalSig, setElgamalSig] = useState(null);
  const [elgamalVerify, setElgamalVerify] = useState(null);
  const [elgamalLoading, setElgamalLoading] = useState(false);

  // Auto-generate initial RSA keys if empty
  useEffect(() => {
    fetchKeys();
    fetchElgamalKeys();
    runDhStep(1);
  }, []);

  const fetchKeys = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/rsa/generate`);
      if (res.ok) {
        const data = await res.json();
        setPublicKeyPem(data.public_key_pem);
        setPrivateKeyPem(data.private_key_pem);
      }
    } catch (e) {
      console.warn("Project 1 backend offline or unreachable", e);
    }
  };

  const fetchElgamalKeys = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/elgamal/keygen`);
      if (res.ok) {
        const data = await res.json();
        setElgamalKeys(data);
      }
    } catch (e) {
      console.warn(e);
    }
  };

  // ---------------- PKI Handlers ----------------
  const handleRegister = async () => {
    setAuthLoading(true);
    setPkiStatus('');
    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        setCurrentUser(data);
        setPublicKeyPem(data.public_key_pem);
        setPrivateKeyPem(data.private_key_pem);
        setPkiStatus(`Success: Registered user '${username}'. Generated RSA-2048 keypair and issued X.509 CA certificate.`);
      } else {
        setPkiStatus(`Error: ${data.error}`);
      }
    } catch (e) {
      setPkiStatus(`Network error: ${e.message}`);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogin = async () => {
    setAuthLoading(true);
    setPkiStatus('');
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        setCurrentUser(data);
        setPublicKeyPem(data.public_key_pem);
        setPrivateKeyPem(data.private_key_pem);
        setPkiStatus(`Success: Logged in as '${username}'. Retained public key and X.509 certificate.`);
      } else {
        setPkiStatus(`Login Failed: ${data.error}`);
      }
    } catch (e) {
      setPkiStatus(`Error: ${e.message}`);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleDownloadCert = () => {
    if (!currentUser?.username) return;
    window.open(`${API_BASE}/api/pki/download-cert/${currentUser.username}`, '_blank');
  };

  // ---------------- RSA Handlers ----------------
  const handleRsaEncrypt = async () => {
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/rsa/encrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key_pem: publicKeyPem, plaintext: rsaPlaintext })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaCiphertext(data.ciphertext_base64);
      } else {
        alert(data.error);
      }
    } catch (e) {
      alert(e.message);
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaDecrypt = async () => {
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/rsa/decrypt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key_pem: privateKeyPem, ciphertext_base64: rsaCiphertext })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaDecrypted(data.plaintext);
      } else {
        alert(data.error);
      }
    } catch (e) {
      alert(e.message);
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaSign = async () => {
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/rsa/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ private_key_pem: privateKeyPem, message: rsaPlaintext })
      });
      const data = await res.json();
      if (res.ok) {
        setRsaSignature(data.signature_base64);
        setRsaVerifyResult(null);
      } else {
        alert(data.error);
      }
    } catch (e) {
      alert(e.message);
    } finally {
      setRsaLoading(false);
    }
  };

  const handleRsaVerify = async () => {
    setRsaLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/rsa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          public_key_pem: publicKeyPem,
          message: rsaPlaintext,
          signature_base64: rsaSignature
        })
      });
      const data = await res.json();
      setRsaVerifyResult(data);
    } catch (e) {
      alert(e.message);
    } finally {
      setRsaLoading(false);
    }
  };

  // ---------------- Diffie-Hellman Handler ----------------
  const runDhStep = async (stepNum) => {
    setDhLoading(true);
    setDhStep(stepNum);
    try {
      const res = await fetch(`${API_BASE}/api/dh/calculate-step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          step: stepNum,
          p: parseInt(dhPrime),
          g: parseInt(dhGen),
          alice_private: parseInt(alicePriv),
          bob_private: parseInt(bobPriv)
        })
      });
      const data = await res.json();
      setDhResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setDhLoading(false);
    }
  };

  // ---------------- Elgamal & SHA-512 Handlers ----------------
  const handleElgamalHash = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/elgamal/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: elgamalMsg })
      });
      const data = await res.json();
      setElgamalHash(data.sha512_hex);
    } catch (e) {
      alert(e.message);
    }
  };

  const handleElgamalSign = async () => {
    if (!elgamalKeys) return;
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/elgamal/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: elgamalMsg,
          private_key_x: elgamalKeys.private_key_x,
          p: elgamalKeys.p,
          g: elgamalKeys.g
        })
      });
      const data = await res.json();
      setElgamalSig(data);
      setElgamalHash(data.sha512_hex);
      setElgamalVerify(null);
    } catch (e) {
      alert(e.message);
    } finally {
      setElgamalLoading(false);
    }
  };

  const handleElgamalVerify = async () => {
    if (!elgamalSig || !elgamalKeys) return;
    setElgamalLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/elgamal/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: elgamalMsg,
          signature_r: elgamalSig.signature_r,
          signature_s: elgamalSig.signature_s,
          public_key_y: elgamalKeys.public_key_y,
          p: elgamalKeys.p,
          g: elgamalKeys.g
        })
      });
      const data = await res.json();
      setElgamalVerify(data);
    } catch (e) {
      alert(e.message);
    } finally {
      setElgamalLoading(false);
    }
  };

  return (
    <div>
      {/* Module Title */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={22} /> Project 1: "CryptoVault"
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
            A Public-Key Cryptography & Digital Signature Toolkit (RSA, Diffie-Hellman, Elgamal, SHA-512, PKI & X.509)
          </p>
        </div>
        <span className="badge badge-blue">Backend: Port 5001</span>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="sub-nav">
        <button className={`sub-nav-btn ${activeTab === 'pki' ? 'active' : ''}`} onClick={() => setActiveTab('pki')}>
          <FileCheck size={15} /> 1. User PKI & X.509 CA
        </button>
        <button className={`sub-nav-btn ${activeTab === 'rsa' ? 'active' : ''}`} onClick={() => setActiveTab('rsa')}>
          <Lock size={15} /> 2. Interactive RSA Module
        </button>
        <button className={`sub-nav-btn ${activeTab === 'dh' ? 'active' : ''}`} onClick={() => setActiveTab('dh')}>
          <RefreshCw size={15} /> 3. Diffie-Hellman Visualizer
        </button>
        <button className={`sub-nav-btn ${activeTab === 'elgamal' ? 'active' : ''}`} onClick={() => setActiveTab('elgamal')}>
          <Hash size={15} /> 4. Elgamal Signature & SHA-512
        </button>
      </div>

      {/* ---------------- 1. PKI & USER AUTH ---------------- */}
      {activeTab === 'pki' && (
        <div className="grid-2">
          <div className="card">
            <h3 className="card-title"><Key size={18} color="#38bdf8" /> User Authentication & Key Registration</h3>
            <p className="card-sub">
              Stallings PKI Simulation: Upon registration, backend generates an RSA-2048 keypair, stores public key in SQLite DB, and issues a self-signed X.509 certificate.
            </p>

            <div className="form-group">
              <label className="form-label">Username</label>
              <input className="form-input" value={username} onChange={e => setUsername(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" value={password} onChange={e => setPassword(e.target.value)} />
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem' }}>
              <button className="btn btn-primary" onClick={handleRegister} disabled={authLoading}>
                Register & Issue Cert
              </button>
              <button className="btn btn-secondary" onClick={handleLogin} disabled={authLoading}>
                Login
              </button>
            </div>

            {pkiStatus && (
              <div style={{ marginTop: '1rem', padding: '0.75rem', background: '#090d16', borderRadius: '6px', fontSize: '0.85rem', color: pkiStatus.startsWith('Error') ? '#f87171' : '#34d399', border: '1px solid #1e293b' }}>
                {pkiStatus}
              </div>
            )}
          </div>

          <div className="card">
            <h3 className="card-title"><FileCheck size={18} color="#10b981" /> X.509 Digital Certificate Authority (CA)</h3>
            <p className="card-sub">Simulates application as Certificate Authority binding user identity to public key.</p>

            {currentUser?.x509_certificate_pem ? (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span className="badge badge-green">Certificate Issued for {currentUser.username}</span>
                  <button className="btn btn-success" style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }} onClick={handleDownloadCert}>
                    <Download size={14} /> Download .crt
                  </button>
                </div>
                <div className="key-display">{currentUser.x509_certificate_pem}</div>
                <div style={{ marginTop: '0.75rem', fontSize: '0.78rem', color: '#94a3b8' }}>
                  <strong>Subject / Issuer:</strong> CN={currentUser.username}, O=CryptoVault CA, C=IN<br />
                  <strong>Validity:</strong> 365 Days • <strong>Signature Algorithm:</strong> SHA256-RSA (2048 bit)
                </div>
              </div>
            ) : (
              <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b', background: '#090d16', borderRadius: '6px' }}>
                Register or login a user to generate and view their X.509 CA Certificate.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ---------------- 2. INTERACTIVE RSA MODULE ---------------- */}
      {activeTab === 'rsa' && (
        <div>
          <div className="grid-2">
            <div className="card">
              <h3 className="card-title"><Lock size={18} color="#38bdf8" /> RSA Operations (OAEP & PSS)</h3>
              <p className="card-sub">Transform plaintext to ciphertext and back; create and verify digital signatures.</p>

              <div className="form-group">
                <label className="form-label">Input Plaintext Message</label>
                <textarea className="form-textarea" value={rsaPlaintext} onChange={e => setRsaPlaintext(e.target.value)} />
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <button className="btn btn-primary" onClick={handleRsaEncrypt} disabled={rsaLoading}>
                  <Lock size={14} /> Encrypt (OAEP)
                </button>
                <button className="btn btn-secondary" onClick={handleRsaDecrypt} disabled={rsaLoading || !rsaCiphertext}>
                  <Unlock size={14} /> Decrypt (OAEP)
                </button>
                <button className="btn btn-purple" onClick={handleRsaSign} disabled={rsaLoading}>
                  <Shield size={14} /> Sign (PSS)
                </button>
                <button className="btn btn-success" onClick={handleRsaVerify} disabled={rsaLoading || !rsaSignature}>
                  <CheckCircle2 size={14} /> Verify Signature
                </button>
              </div>

              {rsaCiphertext && (
                <div style={{ marginBottom: '1rem' }}>
                  <label className="form-label">Ciphertext (Base64)</label>
                  <div className="code-block">{rsaCiphertext}</div>
                </div>
              )}

              {rsaDecrypted && (
                <div style={{ marginBottom: '1rem' }}>
                  <label className="form-label">Decrypted Plaintext</label>
                  <div style={{ padding: '0.6rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #059669', borderRadius: '6px', color: '#34d399', fontSize: '0.85rem' }}>
                    {rsaDecrypted}
                  </div>
                </div>
              )}

              {rsaSignature && (
                <div style={{ marginBottom: '1rem' }}>
                  <label className="form-label">Digital Signature (Base64)</label>
                  <div className="code-block" style={{ color: '#c084fc' }}>{rsaSignature}</div>
                </div>
              )}

              {rsaVerifyResult && (
                <div style={{ padding: '0.75rem', borderRadius: '6px', background: rsaVerifyResult.is_valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)', border: `1px solid ${rsaVerifyResult.is_valid ? '#059669' : '#dc2626'}`, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  {rsaVerifyResult.is_valid ? <CheckCircle2 color="#34d399" /> : <XCircle color="#f87171" />}
                  <span style={{ fontSize: '0.85rem', color: rsaVerifyResult.is_valid ? '#34d399' : '#f87171', fontWeight: 600 }}>
                    {rsaVerifyResult.message || rsaVerifyResult.error}
                  </span>
                </div>
              )}
            </div>

            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <h3 className="card-title"><Key size={18} color="#38bdf8" /> RSA Key Pair (PEM Format)</h3>
                <button className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }} onClick={fetchKeys}>
                  <RefreshCw size={12} /> Regenerate
                </button>
              </div>
              <p className="card-sub">2048-bit RSA keys encoded in PKCS#8 and SubjectPublicKeyInfo PEM formats.</p>

              <div className="form-group">
                <label className="form-label">Public Key (Shared for Encryption & Verification)</label>
                <div className="key-display">{publicKeyPem}</div>
              </div>

              <div className="form-group">
                <label className="form-label">Private Key (Secret for Decryption & Signing)</label>
                <div className="key-display" style={{ color: '#fbcfe8' }}>{privateKeyPem}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ---------------- 3. DIFFIE-HELLMAN KEY EXCHANGE ---------------- */}
      {activeTab === 'dh' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h3 className="card-title"><RefreshCw size={18} color="#38bdf8" /> Diffie-Hellman Key Exchange Visualizer</h3>
              <p className="card-sub">Simulates secure shared secret agreement between Alice and Bob over an insecure public channel.</p>
            </div>
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              <button className={`btn ${dhStep === 1 ? 'btn-primary' : 'btn-secondary'}`} onClick={() => runDhStep(1)}>1. Private Keys</button>
              <button className={`btn ${dhStep === 2 ? 'btn-primary' : 'btn-secondary'}`} onClick={() => runDhStep(2)}>2. Public Keys</button>
              <button className={`btn ${dhStep === 3 ? 'btn-primary' : 'btn-secondary'}`} onClick={() => runDhStep(3)}>3. Exchange</button>
              <button className={`btn ${dhStep === 4 ? 'btn-success' : 'btn-secondary'}`} onClick={() => runDhStep(4)}>4. Shared Secret</button>
            </div>
          </div>

          {/* Public Parameters */}
          <div style={{ background: '#090d16', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b', marginBottom: '1.25rem', display: 'flex', gap: '2rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase' }}>Public Prime (p):</span>
              <strong style={{ marginLeft: '0.5rem', color: '#38bdf8', fontSize: '0.95rem' }}>{dhPrime}</strong>
            </div>
            <div>
              <span style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase' }}>Generator (g):</span>
              <strong style={{ marginLeft: '0.5rem', color: '#38bdf8', fontSize: '0.95rem' }}>{dhGen}</strong>
            </div>
            <div style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
              Public domain parameters known to everyone, including eavesdroppers.
            </div>
          </div>

          {/* Alice & Bob Dual Panels */}
          <div className="grid-2">
            {/* Alice Panel */}
            <div style={{ background: 'rgba(14, 165, 233, 0.08)', border: '1px solid #0284c7', borderRadius: '8px', padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <h4 style={{ color: '#38bdf8', fontWeight: 700, fontSize: '1.05rem' }}>Alice (Party A)</h4>
                <span className="badge badge-blue">Private: a = {alicePriv}</span>
              </div>
              <div className="form-group">
                <label className="form-label">Alice's Secret Key (a)</label>
                <input className="form-input" type="number" value={alicePriv} onChange={e => setAlicePriv(e.target.value)} />
              </div>

              {dhResult?.alice && (
                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '0.85rem' }}>
                  {dhResult.alice.formula && <div style={{ color: '#a5f3fc' }}><strong>Calculation:</strong> {dhResult.alice.formula}</div>}
                  {dhResult.alice.public_key !== undefined && <div style={{ color: '#38bdf8', marginTop: '0.3rem' }}><strong>Public Key A = {dhResult.alice.public_key}</strong></div>}
                </div>
              )}

              {dhStep === 4 && dhResult?.alice_computation && (
                <div style={{ marginTop: '0.75rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #059669', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.8rem', color: '#6ee7b7' }}>{dhResult.alice_computation.formula}</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#34d399', marginTop: '0.3rem' }}>
                    Shared Secret: {dhResult.alice_computation.shared_secret}
                  </div>
                </div>
              )}
            </div>

            {/* Bob Panel */}
            <div style={{ background: 'rgba(139, 92, 246, 0.08)', border: '1px solid #7c3aed', borderRadius: '8px', padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <h4 style={{ color: '#a78bfa', fontWeight: 700, fontSize: '1.05rem' }}>Bob (Party B)</h4>
                <span className="badge badge-purple">Private: b = {bobPriv}</span>
              </div>
              <div className="form-group">
                <label className="form-label">Bob's Secret Key (b)</label>
                <input className="form-input" type="number" value={bobPriv} onChange={e => setBobPriv(e.target.value)} />
              </div>

              {dhResult?.bob && (
                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '0.85rem' }}>
                  {dhResult.bob.formula && <div style={{ color: '#e9d5ff' }}><strong>Calculation:</strong> {dhResult.bob.formula}</div>}
                  {dhResult.bob.public_key !== undefined && <div style={{ color: '#a78bfa', marginTop: '0.3rem' }}><strong>Public Key B = {dhResult.bob.public_key}</strong></div>}
                </div>
              )}

              {dhStep === 4 && dhResult?.bob_computation && (
                <div style={{ marginTop: '0.75rem', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #059669', padding: '0.75rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.8rem', color: '#6ee7b7' }}>{dhResult.bob_computation.formula}</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#34d399', marginTop: '0.3rem' }}>
                    Shared Secret: {dhResult.bob_computation.shared_secret}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Channel Transmission Info */}
          {dhStep === 3 && dhResult?.channel_transmission && (
            <div style={{ marginTop: '1.25rem', padding: '1rem', background: '#090d16', border: '1px solid #334155', borderRadius: '8px' }}>
              <h4 style={{ color: '#fbbf24', fontSize: '0.9rem', marginBottom: '0.5rem' }}>Insecure Public Channel Transmission:</h4>
              <p style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>• {dhResult.channel_transmission.alice_to_bob}</p>
              <p style={{ fontSize: '0.85rem', color: '#f1f5f9' }}>• {dhResult.channel_transmission.bob_to_alice}</p>
              <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: '#94a3b8' }}>
                <span style={{ color: '#ef4444' }}>Eavesdropper's view:</span> Only knows p, g, A, and B. Computing secret 'a' or 'b' requires solving the Discrete Logarithm Problem (computationally infeasible for large primes).
              </div>
            </div>
          )}

          {dhStep === 4 && dhResult?.match && (
            <div style={{ marginTop: '1.25rem', padding: '1rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #059669', borderRadius: '8px', textAlign: 'center' }}>
              <h4 style={{ color: '#34d399', fontSize: '1.1rem', fontWeight: 700 }}>Key Agreement Verified! Both Secrets Match!</h4>
              <p style={{ color: '#a7f3d0', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                {dhResult.explanation}
              </p>
            </div>
          )}
        </div>
      )}

      {/* ---------------- 4. ELGAMAL SIGNATURE & SHA-512 ---------------- */}
      {activeTab === 'elgamal' && (
        <div className="card">
          <h3 className="card-title"><Hash size={18} color="#38bdf8" /> Elgamal Digital Signature Scheme & SHA-512 Hashing</h3>
          <p className="card-sub">
            Demonstrates why cryptographic hashing (SHA-512) is vital before digital signing to compress arbitrary-length messages and resist existential forgery.
          </p>

          <div className="grid-2">
            <div>
              <div className="form-group">
                <label className="form-label">Message to Sign</label>
                <textarea className="form-textarea" value={elgamalMsg} onChange={e => setElgamalMsg(e.target.value)} />
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <button className="btn btn-secondary" onClick={handleElgamalHash}>
                  <Hash size={14} /> Compute SHA-512
                </button>
                <button className="btn btn-primary" onClick={handleElgamalSign} disabled={elgamalLoading}>
                  <Shield size={14} /> Sign Hash with Elgamal
                </button>
                <button className="btn btn-success" onClick={handleElgamalVerify} disabled={elgamalLoading || !elgamalSig}>
                  <CheckCircle2 size={14} /> Verify Signature
                </button>
              </div>

              {elgamalHash && (
                <div style={{ marginBottom: '1rem' }}>
                  <label className="form-label">SHA-512 Digest (512 bits / 64 bytes hex)</label>
                  <div className="code-block" style={{ color: '#38bdf8' }}>{elgamalHash}</div>
                </div>
              )}
            </div>

            <div>
              {elgamalKeys && (
                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b', marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Elgamal Parameters:</div>
                  <div style={{ fontSize: '0.82rem', color: '#e2e8f0' }}>Prime p: <code>{elgamalKeys.p}</code> | Generator g: <code>{elgamalKeys.g}</code></div>
                  <div style={{ fontSize: '0.82rem', color: '#34d399' }}>Public Key y: <code>{elgamalKeys.public_key_y}</code> (g^x mod p)</div>
                  <div style={{ fontSize: '0.82rem', color: '#f472b6' }}>Private Key x: <code>{elgamalKeys.private_key_x}</code> (Secret)</div>
                </div>
              )}

              {elgamalSig && (
                <div style={{ background: '#090d16', padding: '0.75rem', borderRadius: '6px', border: '1px solid #1e293b', marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: '#a78bfa', textTransform: 'uppercase', marginBottom: '0.3rem' }}>Digital Signature (r, s):</div>
                  <div style={{ fontSize: '0.85rem', color: '#f1f5f9' }}><strong>r = </strong> {elgamalSig.signature_r}</div>
                  <div style={{ fontSize: '0.85rem', color: '#f1f5f9' }}><strong>s = </strong> {elgamalSig.signature_s}</div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.4rem' }}>{elgamalSig.explanation}</div>
                </div>
              )}

              {elgamalVerify && (
                <div style={{ padding: '0.75rem', borderRadius: '6px', background: elgamalVerify.is_valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)', border: `1px solid ${elgamalVerify.is_valid ? '#059669' : '#dc2626'}` }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: elgamalVerify.is_valid ? '#34d399' : '#f87171', fontWeight: 700, fontSize: '0.9rem' }}>
                    {elgamalVerify.is_valid ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                    Signature Verification: {elgamalVerify.status}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#cbd5e1', marginTop: '0.4rem' }}>
                    <div>LHS: {elgamalVerify.v1_left_hand_side}</div>
                    <div>RHS: {elgamalVerify.v2_right_hand_side}</div>
                    <div style={{ marginTop: '0.2rem', color: '#38bdf8' }}>Condition: {elgamalVerify.comparison}</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

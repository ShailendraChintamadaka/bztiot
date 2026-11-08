import React from "react";
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldCheck, KeyRound, Info } from 'lucide-react';
import Layout from '../components/Layout';
import { API } from '../api';
import { Card } from '../components/UI';

export default function RegisterDevice() {
  const nav = useNavigate();
  const [f, setF] = useState({ code: '', type: 'Temperature Sensor', key: '', hash: '' });
  const [error, setError] = useState('');
  const set = (k, v) => setF({ ...f, [k]: v });

  async function submit(e) {
    e.preventDefault();
    setError('');

    const payload = {
      deviceCode: f.code,
      deviceType: f.type,
      publicKey: f.key,
      expectedFirmwareHash: f.hash
    };

    const res = await fetch(`${API}/api/devices`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.status === 201) {
      nav('/devices');
    } else if (res.status === 409) {
      setError('That device code is already registered.');
    } else if (res.status === 401 || res.status === 403) {
      setError('Session expired — please log in again.');
    } else {
      setError(`Registration failed (status ${res.status}).`);
    }
  }

  return (
    <Layout title="Register Device" subtitle="Add an IoT device to the security registry.">
      <div className="form-layout">
        <Card>
          <h2>Device Identity</h2>
          <p className="muted">Information used to establish and verify device identity.</p>
          <form onSubmit={submit} className="form">
            <label>Device Code *</label>
            <input required value={f.code} onChange={e => set('code', e.target.value)} placeholder="ESP32_010" />

            <label>Device Type *</label>
            <select value={f.type} onChange={e => set('type', e.target.value)}>
              <option>Temperature Sensor</option>
              <option>Humidity Sensor</option>
              <option>Environmental Sensor</option>
              <option>Motion Sensor</option>
            </select>

            <label>Public Key *</label>
            <textarea required rows="4" value={f.key} onChange={e => set('key', e.target.value)} placeholder="Paste device public key..." />

            <label>Expected Firmware Hash</label>
            <input value={f.hash} onChange={e => set('hash', e.target.value)} placeholder="SHA-256 firmware hash" />

            <div className="info"><Info size={16} /> Private key remains on the IoT device.</div>
            {error && <div className="error">{error}</div>}

            <div className="form-actions">
              <Link className="secondary" to="/devices">Cancel</Link>
              <button className="primary"><ShieldCheck size={16} /> Register Device</button>
            </div>
          </form>
        </Card>
        <Card>
          <small>REGISTRATION FLOW</small>
          <h2>Device identity lifecycle</h2>
          {[['01', 'Generate keys'], ['02', 'Register public identity'], ['03', 'Authenticate'], ['04', 'Continuous monitoring']].map(x =>
            <div className="step" key={x[0]}>
              <i>{x[0]}</i>
              <div><b>{x[1]}</b><p>{x[0] === '01' ? 'Device creates its public/private key pair.' : x[0] === '02' ? 'Public key and metadata enter the registry.' : x[0] === '03' ? 'Challenge-response verifies private-key possession.' : 'Zero Trust evaluates the device after authentication.'}</p></div>
            </div>)}
          <div className="info"><KeyRound size={16} /> Never store private keys in the backend.</div>
        </Card>
      </div>
    </Layout>
  );
}
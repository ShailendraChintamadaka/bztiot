import React, { useEffect, useState } from "react";
import { Link } from 'react-router-dom';
import { Cpu, Plus, Search, Eye } from 'lucide-react';
import Layout from '../components/Layout';
import { API } from '../api';
import { Card, Badge, Risk } from '../components/UI';

export default function Devices() {
  const [q, setQ] = useState('');
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/devices`, { credentials: 'include' })
      .then(res => res.json())
      .then(data => { setDevices(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const rows = devices.filter(d =>
    (d.deviceCode + d.deviceType).toLowerCase().includes(q.toLowerCase())
  );

  return (
    <Layout title="Device Management" subtitle="Register, monitor and manage IoT device identity and security state."
      action={<Link className="primary" to="/devices/register"><Plus size={16} /> Register Device</Link>}>
      <div className="toolbar">
        <div className="search"><Search size={16} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Search device ID or type..." /></div>
        <span>All devices · {devices.length}</span>
        <span>Active · {devices.filter(d => d.status === 'ACTIVE').length}</span>
        <span>Quarantined · {devices.filter(d => d.status === 'QUARANTINED').length}</span>
      </div>
      <Card>
        <div className="table scroll">
          <div className="tr th"><span>Device</span><span>Type</span><span>Firmware</span><span>Risk</span><span>Status</span><span>Registered</span><span /></div>
          {loading && <div className="tr"><span>Loading...</span></div>}
          {!loading && rows.length === 0 && <div className="tr"><span>No devices registered yet.</span></div>}
          {rows.map(d =>
            <div className="tr" key={d.id}>
              <span><Link to={'/devices/' + d.deviceCode} className="device"><i><Cpu size={16} /></i><b>{d.deviceCode}<small>{d.deviceType}</small></b></Link></span>
              <span>{d.deviceType}</span>
              <span className="mono">{d.expectedFirmwareHash ? d.expectedFirmwareHash.slice(0, 12) + '...' : '—'}</span>
              <Risk score={d.trustScore ?? 0} />
              <Badge>{d.status}</Badge>
              <span>{d.registeredAt ? new Date(d.registeredAt).toLocaleString() : '—'}</span>
              <Link to={'/devices/' + d.deviceCode} className="eye"><Eye size={15} /></Link>
            </div>)}
        </div>
      </Card>
    </Layout>
  );
}
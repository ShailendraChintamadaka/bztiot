import React, { useEffect, useState, useCallback } from "react";
import { Link, useNavigate } from 'react-router-dom';
import { Cpu, ShieldCheck, ShieldAlert, Ban, Plus, ArrowUpRight, RefreshCw } from 'lucide-react';
import Layout from '../components/Layout';
import { Card, Badge } from '../components/UI';

// ─── helpers ────────────────────────────────────────────────────────────────

function timeAgo(isoString) {
  if (!isoString) return '—';
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function severityClass(s) {
  if (!s) return '';
  const m = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'low' };
  return m[s.toLowerCase()] ?? '';
}

// ─── component ──────────────────────────────────────────────────────────────

export default function Dashboard() {
  const nav = useNavigate();

  const [stats,  setStats]  = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(Date.now());

  // Auth guard
  useEffect(() => {
    fetch('/api/auth/me', { credentials: 'include' })
      .then(res => { if (res.status === 401) nav('/login'); })
      .catch(() => nav('/login'));
  }, [nav]);

  // Fetch dashboard data
  const fetchData = useCallback(() => {
    setLoading(true);
    Promise.all([
      fetch('/api/dashboard/stats',  { credentials: 'include' }).then(r => r.json()),
      fetch('/api/dashboard/events', { credentials: 'include' }).then(r => r.json()),
    ])
      .then(([s, e]) => {
        setStats(s);
        setEvents(Array.isArray(e) ? e : []);
        setLastRefresh(Date.now());
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-refresh every 15 seconds
  useEffect(() => {
    const id = setInterval(fetchData, 15_000);
    return () => clearInterval(id);
  }, [fetchData]);

  const dist = stats?.riskDistribution ?? {};
  const total = stats?.totalDevices ?? 0;
  const pct = (n) => total === 0 ? 0 : Math.round((Number(n) / total) * 100);

  return (
    <Layout
      title="Security Overview"
      subtitle="Monitor IoT devices, security posture and Zero Trust evaluation activity."
      action={<Link className="primary" to="/devices/register"><Plus size={16} /> Register Device</Link>}
    >
      {/* ── Stat cards ── */}
      <div className="stats">
        <Stat I={Cpu}        n={loading ? '…' : stats?.totalDevices  ?? 0} l="Total Devices" />
        <Stat I={ShieldCheck} n={loading ? '…' : stats?.activeDevices ?? 0} l="Active Devices"  green />
        <Stat I={ShieldAlert} n={loading ? '…' : stats?.highRisk      ?? 0} l="High Risk"       orange />
        <Stat I={Ban}         n={loading ? '…' : stats?.quarantined   ?? 0} l="Quarantined"     red />
      </div>

      <div className="two">
        {/* ── Security Activity ── */}
        <Card>
          <Head
            t="Security Activity"
            s="Recent events detected by the Zero Trust engine"
            link="/security"
            extra={
              <button
                className="refresh-btn"
                onClick={fetchData}
                title="Refresh"
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '4px' }}
              >
                <RefreshCw size={14} />
              </button>
            }
          />
          {loading && <div className="tr"><span style={{ color: 'var(--text-muted)' }}>Loading…</span></div>}
          {!loading && events.length === 0 && (
            <div className="tr"><span style={{ color: 'var(--text-muted)' }}>No security events yet. Start Wokwi to generate data.</span></div>
          )}
          {events.slice(0, 6).map((e, i) => (
            <div className="event" key={e.id ?? i}>
              <i className={'dot ' + severityClass(e.severity)} />
              <div>
                <b>{e.eventType?.replace(/_/g, ' ')}</b>
                <small>{e.deviceCode}</small>
              </div>
              <Badge>{e.severity ?? 'INFO'}</Badge>
              <time>{timeAgo(e.createdAt)}</time>
            </div>
          ))}
        </Card>

        {/* ── Risk Distribution ── */}
        <Card>
          <Head t="Risk Distribution" s="Current device trust posture" />
          {loading
            ? <div style={{ color: 'var(--text-muted)', padding: '16px 0' }}>Loading…</div>
            : (
              <div className="distribution">
                {[
                  ['Low (≥80)',     dist.low      ?? 0, pct(dist.low)],
                  ['Medium (60‑79)', dist.medium   ?? 0, pct(dist.medium)],
                  ['High (40‑59)',   dist.high     ?? 0, pct(dist.high)],
                  ['Critical (<40)', dist.critical ?? 0, pct(dist.critical)],
                ].map(x => (
                  <div key={x[0]}>
                    <span>{x[0]} <b>{x[1]}</b></span>
                    <i><em style={{ width: x[2] + '%' }} /></i>
                  </div>
                ))}
              </div>
            )
          }
          <div className="overall">
            Overall fleet risk{' '}
            <b>
              {loading ? '…' :
                (dist.critical > 0 || dist.high > 0) ? 'HIGH' :
                dist.medium > 0 ? 'MEDIUM' : 'LOW'}
            </b>
          </div>
        </Card>
      </div>

      {/* ── Last refreshed ── */}
      <p style={{ color: 'var(--text-faint)', fontSize: 12, textAlign: 'right', marginTop: 4 }}>
        Last refreshed: {new Date(lastRefresh).toLocaleTimeString()} · auto-refreshes every 15s
      </p>
    </Layout>
  );
}

function Stat({ I, n, l, green, orange, red }) {
  return (
    <div className="stat">
      <div className={'stat-icon ' + (green ? 'green' : orange ? 'orange' : red ? 'red' : '')}><I size={18} /></div>
      <small>{l}</small>
      <strong>{n}</strong>
    </div>
  );
}
function Head({ t, s, link, extra }) {
  return (
    <div className="card-head">
      <div><h2>{t}</h2><p>{s}</p></div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {extra}
        {link && <Link to={link}>View all <ArrowUpRight size={14} /></Link>}
      </div>
    </div>
  );
}

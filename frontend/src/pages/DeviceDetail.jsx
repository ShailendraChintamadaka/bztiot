import React, { useEffect, useState } from "react";
import { useParams, Link } from 'react-router-dom';
import {
  Cpu, ShieldCheck, ShieldAlert, Ban, ArrowLeft,
  Clock, Fingerprint, Activity, AlertTriangle
} from 'lucide-react';
import Layout from '../components/Layout';
import { Card, Badge } from '../components/UI';

// ─── helpers ────────────────────────────────────────────────────────────────

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(iso).toLocaleString();
}

function trustColor(score) {
  if (score >= 80) return 'var(--trust)';
  if (score >= 60) return 'var(--warn)';
  if (score >= 40) return 'var(--alert)';
  return 'var(--critical)';
}

function trustLabel(score) {
  if (score >= 80) return 'ALLOW';
  if (score >= 60) return 'RESTRICT';
  if (score >= 40) return 'QUARANTINE';
  return 'DENY';
}

// Mini horizontal bar
function ScoreBar({ label, value, color }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{label}</span>
        <span style={{ fontWeight: 600, fontSize: 12, color }}>{value}</span>
      </div>
      <div style={{ background: 'var(--border)', borderRadius: 4, height: 6 }}>
        <div style={{ width: value + '%', background: color, height: 6, borderRadius: 4, transition: 'width .4s' }} />
      </div>
    </div>
  );
}

// ─── component ──────────────────────────────────────────────────────────────

export default function DeviceDetail() {
  const { deviceCode } = useParams();

  const [device,   setDevice]   = useState(null);
  const [events,   setEvents]   = useState([]);
  const [history,  setHistory]  = useState([]);
  const [decisions, setDecisions] = useState([]);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => {
    if (!deviceCode) return;
    setLoading(true);

    Promise.all([
      fetch(`/api/devices/code/${deviceCode}`, { credentials: 'include' }).then(r => r.ok ? r.json() : null),
      fetch(`/api/security/events/${deviceCode}`, { credentials: 'include' }).then(r => r.json()).catch(() => []),
      fetch(`/api/security/history/${deviceCode}`, { credentials: 'include' }).then(r => r.json()).catch(() => []),
      fetch(`/api/security/decisions/${deviceCode}`, { credentials: 'include' }).then(r => r.json()).catch(() => []),
    ]).then(([d, e, h, dec]) => {
      setDevice(d);
      setEvents(Array.isArray(e) ? e : []);
      setHistory(Array.isArray(h) ? h : []);
      setDecisions(Array.isArray(dec) ? dec : []);
    }).finally(() => setLoading(false));
  }, [deviceCode]);

  if (loading) {
    return (
      <Layout title="Device Detail" subtitle="">
        <p style={{ color: 'var(--text-muted)' }}>Loading device data…</p>
      </Layout>
    );
  }

  if (!device) {
    return (
      <Layout title="Device Not Found" subtitle="">
        <Card>
          <p style={{ color: 'var(--text-muted)' }}>No device found with code <code>{deviceCode}</code>.</p>
          <Link to="/devices" style={{ color: 'var(--trust)', marginTop: 12, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <ArrowLeft size={14} /> Back to Devices
          </Link>
        </Card>
      </Layout>
    );
  }

  const score = device.trustScore ?? 0;
  const latest = history[0]; // most recent trust snapshot

  return (
    <Layout
      title={device.deviceCode}
      subtitle={`${device.deviceType} · Zero Trust device detail`}
      action={
        <Link className="secondary" to="/devices" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <ArrowLeft size={15} /> All Devices
        </Link>
      }
    >
      {/* ── Top summary row ── */}
      <div className="stats" style={{ marginBottom: 24 }}>
        <div className="stat">
          <div className="stat-icon" style={{ background: trustColor(score) + '22' }}>
            <Cpu size={18} style={{ color: trustColor(score) }} />
          </div>
          <small>Trust Score</small>
          <strong style={{ color: trustColor(score) }}>{score}</strong>
        </div>
        <div className="stat">
          <div className={'stat-icon ' + (device.status === 'ACTIVE' ? 'green' : device.status === 'QUARANTINED' ? 'orange' : 'red')}>
            <ShieldCheck size={18} />
          </div>
          <small>Status</small>
          <strong>{device.status}</strong>
        </div>
        <div className="stat">
          <div className="stat-icon">
            <Fingerprint size={18} />
          </div>
          <small>Auth Failures</small>
          <strong style={{ color: device.authFailureCount > 0 ? 'var(--critical)' : 'var(--trust)' }}>
            {device.authFailureCount}
          </strong>
        </div>
        <div className="stat">
          <div className="stat-icon">
            <Clock size={18} />
          </div>
          <small>Last Seen</small>
          <strong style={{ fontSize: 12 }}>{timeAgo(device.lastSeenAt)}</strong>
        </div>
      </div>

      <div className="two">
        {/* ── Trust Score Breakdown ── */}
        <Card>
          <div className="card-head">
            <div><h2>Trust Breakdown</h2><p>T = w1·I + w2·B + w3·H + w4·S</p></div>
            <span style={{
              background: trustColor(score) + '22',
              color: trustColor(score),
              padding: '4px 10px', borderRadius: 20, fontSize: 12, fontWeight: 700
            }}>
              {trustLabel(score)}
            </span>
          </div>

          {/* Big score ring */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 24, margin: '20px 0' }}>
            <div style={{
              width: 80, height: 80, borderRadius: '50%',
              border: `6px solid ${trustColor(score)}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0
            }}>
              <span style={{ fontSize: 22, fontWeight: 700, color: trustColor(score) }}>{score}</span>
            </div>
            <div style={{ flex: 1 }}>
              {latest ? (
                <>
                  <ScoreBar label="Identity (w1 = 35%)"        value={latest.identityScore}      color="var(--trust)" />
                  <ScoreBar label="Behavioral (w2 = 30%)"      value={latest.behavioralScore}    color="var(--warn)" />
                  <ScoreBar label="Historical (w3 = 15%)"      value={latest.historicalScore}    color="var(--alert)" />
                  <ScoreBar label="Security State (w4 = 20%)"  value={latest.securityStateScore} color="var(--critical)" />
                </>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
                  No trust evaluation data yet. The device needs to authenticate and publish MQTT data first.
                </p>
              )}
            </div>
          </div>

          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, marginTop: 4 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Info label="Device Type"   value={device.deviceType} />
              <Info label="Registered"    value={device.registeredAt ? new Date(device.registeredAt).toLocaleDateString() : '—'} />
              <Info label="Last Auth"     value={timeAgo(device.lastAuthAt)} />
              <Info label="Firmware Hash" value={device.expectedFirmwareHash ? device.expectedFirmwareHash.slice(0, 16) + '…' : '—'} mono />
            </div>
          </div>
        </Card>

        {/* ── Recent Security Events ── */}
        <Card>
          <div className="card-head">
            <div><h2>Security Events</h2><p>Auth, firmware, and behavioral events</p></div>
            <AlertTriangle size={16} style={{ color: 'var(--warn)' }} />
          </div>
          {events.length === 0 && (
            <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: '12px 0' }}>No events recorded yet.</p>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
            {events.slice(0, 10).map((ev, i) => (
              <div key={ev.id ?? i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 10,
                padding: '10px 12px', background: 'var(--surface-2)',
                borderRadius: 8, borderLeft: `3px solid ${severityColor(ev.severity)}`
              }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{ev.eventType?.replace(/_/g, ' ')}</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>{ev.detail}</div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
                  <Badge>{ev.severity ?? 'INFO'}</Badge>
                  <time style={{ fontSize: 11, color: 'var(--text-faint)' }}>{timeAgo(ev.createdAt)}</time>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* ── Trust Score History ── */}
      <Card style={{ marginTop: 20 }}>
        <div className="card-head">
          <div><h2>Trust Score History</h2><p>Last 50 evaluations (newest first)</p></div>
          <Activity size={16} style={{ color: 'var(--trust)' }} />
        </div>
        {history.length === 0 && (
          <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: '12px 0' }}>No history yet — device must publish MQTT data first.</p>
        )}
        <div className="table scroll" style={{ marginTop: 12 }}>
          {history.length > 0 && (
            <div className="tr th">
              <span>Score</span><span>Decision</span><span>Identity</span>
              <span>Behavioral</span><span>Historical</span><span>Security</span>
              <span>Trigger</span><span>Time</span>
            </div>
          )}
          {history.slice(0, 20).map((h, i) => (
            <div className="tr" key={h.id ?? i}>
              <span style={{ fontWeight: 700, color: trustColor(h.trustScore) }}>{h.trustScore}</span>
              <span><Badge>{h.accessDecision}</Badge></span>
              <span>{h.identityScore}</span>
              <span>{h.behavioralScore}</span>
              <span>{h.historicalScore}</span>
              <span>{h.securityStateScore}</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{h.triggerEvent}</span>
              <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>{timeAgo(h.recordedAt)}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* ── Access Decisions ── */}
      <Card style={{ marginTop: 20 }}>
        <div className="card-head">
          <div><h2>Access Decisions</h2><p>Every MQTT publish policy outcome</p></div>
          <ShieldAlert size={16} style={{ color: 'var(--warn)' }} />
        </div>
        {decisions.length === 0 && (
          <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: '12px 0' }}>No access decisions recorded yet.</p>
        )}
        <div className="table scroll" style={{ marginTop: 12 }}>
          {decisions.length > 0 && (
            <div className="tr th">
              <span>Decision</span><span>Score</span><span>Enforced</span><span>Reason</span><span>Time</span>
            </div>
          )}
          {decisions.slice(0, 20).map((d, i) => (
            <div className="tr" key={d.id ?? i}>
              <span><Badge>{d.decision}</Badge></span>
              <span style={{ color: trustColor(d.trustScore), fontWeight: 600 }}>{d.trustScore}</span>
              <span style={{ color: d.enforced ? 'var(--critical)' : 'var(--trust)', fontSize: 12 }}>
                {d.enforced ? 'YES — blocked' : 'NO — allowed'}
              </span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {d.reason}
              </span>
              <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>{timeAgo(d.decidedAt)}</span>
            </div>
          ))}
        </div>
      </Card>
    </Layout>
  );
}

function Info({ label, value, mono }) {
  return (
    <div style={{ padding: '6px 0' }}>
      <div style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
      <div style={{ fontSize: 13, fontFamily: mono ? 'var(--font-mono)' : undefined, marginTop: 2 }}>{value || '—'}</div>
    </div>
  );
}

function severityColor(s) {
  if (!s) return 'var(--border)';
  switch (s.toLowerCase()) {
    case 'critical': return 'var(--critical)';
    case 'high':     return 'var(--alert)';
    case 'medium':   return 'var(--warn)';
    default:         return 'var(--trust)';
  }
}


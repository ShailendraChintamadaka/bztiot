import React, { useEffect, useState, useCallback } from "react";
import { Link } from 'react-router-dom';
import { ShieldAlert, RefreshCw, AlertTriangle, AlertOctagon, Info } from 'lucide-react';
import Layout from '../components/Layout';
import { Card, Badge } from '../components/UI';

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60)   return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(iso).toLocaleString();
}

function SevIcon({ s }) {
  if (!s) return <Info size={15} />;
  switch (s.toLowerCase()) {
    case 'critical': return <AlertOctagon size={15} />;
    case 'high':     return <AlertTriangle size={15} />;
    case 'medium':   return <ShieldAlert size={15} />;
    default:         return <Info size={15} />;
  }
}

export default function SecurityEvents() {
  const [events,   setEvents]   = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [filter,   setFilter]   = useState('ALL');   // ALL | CRITICAL | HIGH | MEDIUM | INFO
  const [lastRefresh, setLastRefresh] = useState(Date.now());

  const fetchEvents = useCallback(() => {
    setLoading(true);
    fetch('/api/security/events', { credentials: 'include' })
      .then(r => r.json())
      .then(data => { setEvents(Array.isArray(data) ? data : []); setLastRefresh(Date.now()); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const id = setInterval(fetchEvents, 10_000);
    return () => clearInterval(id);
  }, [fetchEvents]);

  const filtered = filter === 'ALL'
    ? events
    : events.filter(e => (e.severity ?? 'INFO').toUpperCase() === filter);

  const counts = {
    critical: events.filter(e => e.severity === 'CRITICAL').length,
    high:     events.filter(e => e.severity === 'HIGH').length,
    medium:   events.filter(e => e.severity === 'MEDIUM').length,
  };

  const FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  return (
    <Layout
      title="Security Monitoring"
      subtitle="Real-time security events from the Zero Trust evaluation engine."
      action={
        <button
          className="secondary"
          onClick={fetchEvents}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
        >
          <RefreshCw size={14} /> Refresh
        </button>
      }
    >
      {/* ── Summary cards ── */}
      <div className="alert-summary">
        <div>
          <AlertOctagon size={20} style={{ color: 'var(--critical)' }} />
          <b style={{ color: 'var(--critical)' }}>{counts.critical}</b>
          <span>Critical Events</span>
        </div>
        <div>
          <AlertTriangle size={20} style={{ color: 'var(--alert)' }} />
          <b style={{ color: 'var(--alert)' }}>{counts.high}</b>
          <span>High Severity</span>
        </div>
        <div>
          <ShieldAlert size={20} style={{ color: 'var(--warn)' }} />
          <b style={{ color: 'var(--warn)' }}>{counts.medium}</b>
          <span>Medium Severity</span>
        </div>
      </div>

      <Card>
        {/* ── Filter bar ── */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
          {FILTERS.map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '5px 14px', borderRadius: 20, border: '1px solid',
                borderColor: filter === f ? 'var(--trust)' : 'var(--border)',
                background:  filter === f ? 'var(--trust-dim)' : 'transparent',
                color:       filter === f ? 'var(--trust)' : 'var(--text-muted)',
                fontSize: 12, fontWeight: 500, cursor: 'pointer',
              }}
            >
              {f}
              {f !== 'ALL' && (
                <span style={{ marginLeft: 5, opacity: 0.7 }}>
                  ({events.filter(e => (e.severity ?? 'INFO').toUpperCase() === f).length})
                </span>
              )}
            </button>
          ))}
          <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-faint)', alignSelf: 'center' }}>
            {filtered.length} events · refreshed {new Date(lastRefresh).toLocaleTimeString()}
          </span>
        </div>

        {/* ── Event list ── */}
        {loading && <p style={{ color: 'var(--text-muted)' }}>Loading events…</p>}
        {!loading && filtered.length === 0 && (
          <p style={{ color: 'var(--text-muted)', padding: '20px 0' }}>
            {events.length === 0
              ? 'No security events yet. Start the Wokwi simulation to generate data.'
              : `No ${filter} events found.`}
          </p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {filtered.map((ev, i) => (
            <div
              key={ev.id ?? i}
              className={'alert ' + (ev.severity ?? 'info').toLowerCase()}
              style={{ display: 'flex', alignItems: 'flex-start', gap: 14, padding: '14px 4px', borderBottom: '1px solid var(--border-soft)' }}
            >
              <SevIcon s={ev.severity} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <b>{ev.eventType?.replace(/_/g, ' ')}</b>
                  <Badge>{ev.severity ?? 'INFO'}</Badge>
                  {ev.accessDecision && <Badge>{ev.accessDecision}</Badge>}
                </div>
                <p style={{ fontSize: 12.5, lineHeight: 1.5 }}>{ev.detail}</p>
                <small style={{ fontSize: 11.5, color: 'var(--text-faint)', marginTop: 5, display: 'block' }}>
                  {timeAgo(ev.createdAt)}
                  {ev.trustScoreBefore != null && ev.trustScoreAfter != null && (
                    <> · Trust: <span style={{ color: 'var(--warn)' }}>{ev.trustScoreBefore}</span>
                      {' → '}
                      <span style={{ color: ev.trustScoreAfter < ev.trustScoreBefore ? 'var(--critical)' : 'var(--trust)' }}>
                        {ev.trustScoreAfter}
                      </span>
                    </>
                  )}
                </small>
              </div>
              <Link
                to={`/devices/${ev.deviceCode}`}
                className="secondary"
                style={{ padding: '6px 12px', fontSize: 12, flexShrink: 0, alignSelf: 'center' }}
              >
                {ev.deviceCode}
              </Link>
            </div>
          ))}
        </div>
      </Card>
    </Layout>
  );
}


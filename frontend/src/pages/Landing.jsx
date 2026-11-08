import React from "react";
import { Link } from 'react-router-dom';
import { ShieldCheck, Fingerprint, Activity, Blocks, LockKeyhole, Radio, Database, ArrowRight } from 'lucide-react';
import Logo from '../components/Logo';

export default function Landing() {
  return (
    <div className="landing">
      <nav>
        <Logo />
        <div>
          <a href="#security">Security</a>
          <a href="#architecture">Architecture</a>
          <a href="#about">About</a>
          <Link className="nav-login" to="/login">Admin Login <ArrowRight size={15} /></Link>
        </div>
      </nav>

      <section className="hero">
        <div>
          <small className="kicker">● IOT SECURITY CONTROL PLATFORM</small>
          <h1>Blockchain-Based<br /><em>Zero Trust</em> Security<br />for IoT Devices</h1>
          <p>Continuously verify device identity, evaluate security risk, dynamically control access, and preserve critical security events with tamper-evident blockchain auditing.</p>
          <div className="actions">
            <Link className="primary" to="/login">Admin Login <ArrowRight size={17} /></Link>
            <a className="secondary" href="#architecture">Explore Architecture</a>
          </div>
          <div className="points">
            <span><ShieldCheck size={14} /> Continuous Verification</span>
            <span><Fingerprint size={14} /> Device Identity</span>
            <span><Blocks size={14} /> Blockchain Audit</span>
          </div>
        </div>
        <div className="console">
          <div className="console-head">ZERO TRUST ENGINE <b>● ACTIVE</b></div>
          <div className="console-body">
            {[['DEVICE_ID', 'ESP32_001', 'VERIFIED'], ['FIRMWARE', 'SHA-256', 'VALID'], ['MQTT_ACTIVITY', '4 msg/min', 'NORMAL'], ['RISK_SCORE', '12 / 100', 'LOW']].map(x =>
              <div className="console-row" key={x[0]}><span>{x[0]}</span><strong>{x[1]}</strong><b>{x[2]}</b></div>)}
            <div className="decision">
              <ShieldCheck size={22} />
              <div><small>ACCESS DECISION</small><strong>ALLOW</strong></div>
              <span>LIVE</span>
            </div>
          </div>
        </div>
      </section>

      <section id="security" className="section">
        <small>SECURITY MODEL</small>
        <h2>Verify. Evaluate. Enforce.</h2>
        <p>The platform continuously evaluates IoT security posture instead of assuming that a previously authenticated device remains trusted.</p>
        <div className="feature-grid">
          <Feature I={Fingerprint} t="Device Identity" d="Cryptographic identity and challenge-response authentication establish device authenticity." />
          <Feature I={Activity} t="Continuous Risk" d="Firmware state, MQTT behaviour, access patterns and security events contribute to the current risk score." />
          <Feature I={LockKeyhole} t="Dynamic Enforcement" d="Risk-based decisions move devices between Allow, Restrict, Quarantine and Revoke." />
          <Feature I={Blocks} t="Tamper-Evident Audit" d="Important security events are anchored to the private blockchain." />
        </div>
      </section>

      <section id="architecture" className="section arch">
        <small>SYSTEM ARCHITECTURE</small>
        <h2>Security across every layer</h2>
        <div className="arch-flow">
          {[['IoT Devices', 'ESP32 + Sensors', Radio], ['MQTT', 'Secure Messaging', Radio], ['Spring Boot', 'Security Gateway', ShieldCheck], ['Zero Trust', 'Risk + Policy', Activity], ['Besu QBFT', 'Blockchain Audit', Blocks]].map(([a, b, I], i) =>
            <div className="arch-item" key={a}><I size={19} /><b>{a}</b><small>{b}</small>{i < 4 && <span>→</span>}</div>)}
        </div>
        <div className="data-line">
          <span><Database size={15} /> PostgreSQL — operational data</span>
          <span><Blocks size={15} /> Solidity — critical security state</span>
        </div>
      </section>

      <section id="about" className="bottom">
        <div>
          <small>BZTIOT FRAMEWORK</small>
          <h2>Security decisions based on current device state.</h2>
        </div>
        <Link className="primary" to="/login">Open Security Console <ArrowRight size={16} /></Link>
      </section>

      <footer><Logo /> <span>Blockchain-Based Zero Trust Security Framework for IoT Devices</span></footer>
    </div>
  );
}

function Feature({ I, t, d }) {
  return <div className="feature"><div className="ficon"><I size={20} /></div><h3>{t}</h3><p>{d}</p></div>;
}
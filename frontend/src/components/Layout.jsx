import React from "react";
import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Cpu, ShieldAlert, Blocks, Bell, Activity, Plus, LogOut } from 'lucide-react';
import Logo from './Logo';
import { API } from '../api';

const links = [
  ['/dashboard', 'Overview', LayoutDashboard],
  ['/devices', 'Devices', Cpu],
  ['/security', 'Security Monitoring', ShieldAlert],
  ['/blockchain', 'Blockchain Audits', Blocks],
  ['/alerts', 'Security Alerts', Bell],
  ['/system', 'System Status', Activity]
];

export default function Layout({ title, subtitle, children, action }) {
  const nav = useNavigate();

  const logout = () => {
    fetch(`${API}/perform_logout`, { method: 'POST', credentials: 'include' })
      .then(() => nav('/'));
  };

  return (
    <div className="shell">
      <aside>
        <Logo />
        <div className="menu-title">CONTROL CENTER</div>
        {links.map(([to, label, I]) =>
          <NavLink className={({ isActive }) => 'nav ' + (isActive ? 'active' : '')} to={to} key={to}>
            <I size={17} /><span>{label}</span>
          </NavLink>
        )}
        <button className="register" onClick={() => nav('/devices/register')}>
          <Plus size={17} /> Register Device
        </button>
        <div className="side-bottom">
          <div className="admin">
            <span>AD</span>
            <div><b>Administrator</b><small>ADMIN</small></div>
          </div>
          <button onClick={logout}><LogOut size={15} /> Logout</button>
        </div>
      </aside>
      <main>
        <header>
          <span className="online">● SYSTEM ONLINE</span>
          <span>AD &nbsp; Administrator</span>
        </header>
        <div className="content">
          <div className="heading">
            <div>
              <small>SECURITY CONTROL CENTER</small>
              <h1>{title}</h1>
              <p>{subtitle}</p>
            </div>
            {action}
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
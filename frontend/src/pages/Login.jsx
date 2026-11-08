import React from "react";
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Eye, EyeOff, LockKeyhole, ShieldCheck, ArrowLeft } from 'lucide-react';
import Logo from '../components/Logo';

import { API } from '../api';

export default function Login() {
  const [u, setU] = useState(''), [p, setP] = useState(''), [show, setShow] = useState(false), [err, setErr] = useState('');
  const nav = useNavigate();

  async function submit(e) {
      e.preventDefault();
      setErr('');

      const formData = new FormData(e.currentTarget);
      const username = (formData.get('username') || u || '').trim();
      const password = (formData.get('password') || p || '').trim();

      const body = new URLSearchParams();
      body.append('username', username);
      body.append('password', password);

      try {
        const res = await fetch(`${API}/perform_login`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString()
        });

        if (res.status === 200) {
          nav('/dashboard');
        } else {
          setErr(`Invalid administrator credentials (status ${res.status}).`);
        }
      } 
      catch (networkError) {
        setErr('Unable to reach the backend — is it running?');
      }
  }

  return (
    <div className="login">
      <Link className="back" to="/"><ArrowLeft size={15} /> Back to home</Link>
      <div className="login-card">
        <div className="login-icon"><ShieldCheck size={27} /></div>
        <small>ADMINISTRATOR ACCESS</small>
        <h1>Welcome back</h1>
        <p>Sign in to access the IoT security control center.</p>
        <form onSubmit={submit}>
          <label>Username</label>
          <input name="username" value={u} onChange={e => setU(e.target.value)} placeholder="Administrator username" />
          <label>Password</label>
          <div className="pass">
            <input name="password" type={show ? 'text' : 'password'} value={p} onChange={e => setP(e.target.value)} placeholder="Enter password" />
            <button type="button" onClick={() => setShow(!show)}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
          </div>
          {err && <div className="error">{err}</div>}
          <button className="primary full"><LockKeyhole size={16} /> Sign In</button>
        </form>
        <div className="login-note">● Protected administrator console</div>
      </div>
      <div className="login-logo"><Logo /></div>
    </div>
  );
}
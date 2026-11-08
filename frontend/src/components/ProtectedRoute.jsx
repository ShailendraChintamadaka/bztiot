import React, { useEffect, useState } from "react";
import { useNavigate } from 'react-router-dom';
import { API } from '../api';

export default function ProtectedRoute({ children }) {
  const nav = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/auth/me`, { credentials: 'include' })
      .then(res => {
        if (res.status === 401) { nav('/login'); }
        else { setChecking(false); }
      })
      .catch(() => nav('/login'));
  }, [nav]);

  if (checking) return null; // swap for a small spinner later if you want one

  return children;
}
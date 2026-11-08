import { Routes, Route, Navigate } from 'react-router-dom';
import React from "react";
import Landing        from './pages/Landing';
import Login          from './pages/Login';
import Dashboard      from './pages/Dashboard';
import Devices        from './pages/Devices';
import RegisterDevice from './pages/RegisterDevice';
import DeviceDetail   from './pages/DeviceDetail';
import SecurityEvents from './pages/SecurityEvents';
import ProtectedRoute from './components/ProtectedRoute';

export default function App() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/"      element={<Landing />} />
      <Route path="/login" element={<Login />} />

      {/* Protected */}
      <Route path="/dashboard"         element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/devices"           element={<ProtectedRoute><Devices /></ProtectedRoute>} />
      <Route path="/devices/register"  element={<ProtectedRoute><RegisterDevice /></ProtectedRoute>} />
      <Route path="/devices/:deviceCode" element={<ProtectedRoute><DeviceDetail /></ProtectedRoute>} />
      <Route path="/security"          element={<ProtectedRoute><SecurityEvents /></ProtectedRoute>} />

      {/* Catch-all */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

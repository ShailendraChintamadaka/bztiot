import React from "react";
import { ShieldCheck } from 'lucide-react';

export default function Logo() {
  return (
    <div className="brand">
      <div className="brand-mark"><ShieldCheck size={20} /></div>
      <div><b>BZTIoT</b><small>ZERO TRUST SECURITY</small></div>
    </div>
  );
}
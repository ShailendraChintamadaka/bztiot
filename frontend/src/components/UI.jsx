import React from "react";

export function Badge({ children }) {
  return <span className={'badge ' + String(children).toLowerCase()}>{children}</span>;
}

export function Risk({ score }) {
  return (
    <div className="risk">
      <b>{score}</b>
      <span><i className={score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low'} style={{ width: score + '%' }} /></span>
    </div>
  );
}

export function Card({ children, className = '' }) {
  return <section className={'card ' + className}>{children}</section>;
}
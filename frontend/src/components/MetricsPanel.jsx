import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4'];

const StatCard = ({ title, value, subtitle, icon, color }) => (
  <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
    <div className="flex items-center justify-between">
      <div>
        <p className="text-xs text-slate-500 font-medium">{title}</p>
        <p className="text-2xl font-bold text-slate-900 mt-1">{value}</p>
        {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
      </div>
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
        {icon}
      </div>
    </div>
  </div>
);

const MetricsPanel = ({ stats }) => {
  const pieData = Object.entries(stats.attack_types || {}).map(([name, value]) => ({ name, value }));

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      <StatCard
        title="Total Events"
        value={(stats.total_events || 0).toLocaleString()}
        icon={<svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>}
        color="bg-blue-50"
      />
      <StatCard
        title="Attacks Detected"
        value={(stats.attacks_detected || 0).toLocaleString()}
        icon={<svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>}
        color="bg-red-50"
      />
      <StatCard
        title="Correlated Incidents"
        value={(stats.correlated_incidents || 0).toLocaleString()}
        subtitle="Network + Log correlated"
        icon={<svg className="w-5 h-5 text-violet-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4.841 4.841 0 00-6.364 0l-1.414 1.414a4.841 4.841 0 016.364 0l1.414-1.414zm0 0l1.414 1.414a4.841 4.841 0 006.364 0l1.414-1.414a4.841 4.841 0 00-6.364 0l-1.414 1.414z" /></svg>}
        color="bg-violet-50"
      />
      <StatCard
        title="Stored Incidents"
        value={(stats.stored_incidents || 0).toLocaleString()}
        subtitle="In historical database"
        icon={<svg className="w-5 h-5 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>}
        color="bg-amber-50"
      />
    </div>
  );
};

export default MetricsPanel;

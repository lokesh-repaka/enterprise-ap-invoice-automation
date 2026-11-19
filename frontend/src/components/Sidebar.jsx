import React, { useState } from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  AlertTriangle,
  FileSearch,
  ShieldCheck,
  ChevronDown,
} from 'lucide-react';

export default function Sidebar({
  activeTab,
  setActiveTab,
  currentUser,
  setCurrentUser,
  personas,
  systemStatus,
}) {
  const [showDropdown, setShowDropdown] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'upload', label: 'Upload Invoices', icon: UploadCloud },
    {
      id: 'exceptions',
      label: 'Action Required',
      icon: AlertTriangle,
      badge: '3',
      badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    },
    { id: 'workbench', label: 'Review Workbench', icon: FileSearch },
    { id: 'audit', label: 'Audit Trail', icon: ShieldCheck },
  ];

  return (
    <aside className="w-64 bg-[#111827] border-r border-slate-800/80 flex flex-col justify-between flex-shrink-0 z-40 select-none">
      {/* Top Branding & Navigation */}
      <div className="flex flex-col">
        {/* Brand Header */}
        <div className="p-5 flex items-center gap-3 border-b border-slate-800/60">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 via-blue-600 to-cyan-400 flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-tight text-white">Apex<span className="text-indigo-400">AP</span></span>
              <span className="px-1.5 py-0.2 text-[9px] font-bold tracking-wider uppercase rounded bg-indigo-500/15 text-indigo-400 border border-indigo-500/30">Enterprise</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-tight">Accounts Payable Suite</p>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          <div className="px-3 pt-3 pb-1 text-[10px] font-semibold tracking-wider text-slate-400 uppercase">Workflow</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl font-medium text-xs transition-all ${
                  isActive
                    ? 'text-white bg-indigo-600 shadow-md shadow-indigo-600/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${item.id === 'exceptions' && !isActive ? 'text-amber-400' : ''}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status & User Profile Pill */}
      <div className="p-4 border-t border-slate-800/60 space-y-3">
        {/* System Health */}
        <div className="flex items-center justify-between text-xs px-2 text-slate-400">
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>{systemStatus?.status === 'healthy' ? 'System Healthy' : 'Connecting...'}</span>
          </span>
          <span className="text-[10px] text-slate-500 font-mono">v0.1.0</span>
        </div>

        {/* User Profile Card with Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowDropdown(!showDropdown)}
            className="w-full flex items-center justify-between bg-slate-850 hover:bg-slate-800/90 p-2.5 rounded-xl border border-slate-800 transition-colors"
          >
            <div className="flex items-center gap-2.5 text-left">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-xs text-white shadow ${
                currentUser.role === 'finance_manager'
                  ? 'bg-gradient-to-tr from-blue-500 to-cyan-500'
                  : currentUser.role === 'system_admin'
                  ? 'bg-gradient-to-tr from-emerald-500 to-teal-500'
                  : 'bg-gradient-to-tr from-purple-500 to-indigo-500'
              }`}>
                {currentUser.avatar || 'SJ'}
              </div>
              <div>
                <div className="font-semibold text-xs text-white leading-tight">{currentUser.name}</div>
                <div className="text-[10px] text-indigo-400 font-medium">{currentUser.roleTitle}</div>
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-slate-400" />
          </button>

          {/* Role Dropdown Popup */}
          {showDropdown && (
            <div className="absolute bottom-14 left-0 w-64 rounded-xl bg-slate-900 border border-slate-700 shadow-2xl p-2 z-50">
              <div className="px-3 py-2 border-b border-slate-800 mb-1">
                <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">Active User Role</p>
                <p className="text-xs text-slate-300">Simulate workflow role permissions</p>
              </div>
              {personas.map((p) => (
                <button
                  key={p.username}
                  onClick={() => {
                    setCurrentUser(p);
                    setShowDropdown(false);
                  }}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-800 flex items-center gap-2.5 transition"
                >
                  <div className={`w-6 h-6 rounded-full font-bold text-xs flex items-center justify-center ${p.badgeClass}`}>
                    {p.avatar}
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-white">{p.name}</div>
                    <div className="text-[10px] text-slate-400">{p.description}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}

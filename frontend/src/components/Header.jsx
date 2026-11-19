import React from 'react';
import { Search, Plus } from 'lucide-react';

export default function Header({ activeTab, setActiveTab }) {
  const pageTitles = {
    dashboard: 'Executive Dashboard',
    upload: 'Upload Invoices',
    exceptions: 'Action Required',
    workbench: 'Review Workbench',
    audit: 'Audit & Compliance',
  };

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#111827]/70 backdrop-blur-md px-8 flex items-center justify-between flex-shrink-0">
      {/* Title & Search */}
      <div className="flex items-center gap-4">
        <h2 className="font-bold text-base text-white">
          {pageTitles[activeTab] || 'Executive Dashboard'}
        </h2>
        <div className="hidden md:flex items-center bg-slate-900 border border-slate-700/60 rounded-xl px-3 py-1.5 text-xs text-slate-400 w-80">
          <Search className="w-4 h-4 text-slate-500 mr-2 flex-shrink-0" />
          <input
            type="text"
            placeholder="Search by vendor, PO #, or invoice ID..."
            className="bg-transparent text-white focus:outline-none w-full"
          />
        </div>
      </div>

      {/* Action Button */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setActiveTab('upload')}
          className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-xs px-4 py-2 rounded-xl shadow-md shadow-indigo-600/25 transition flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          <span>Upload Invoices</span>
        </button>
      </div>
    </header>
  );
}

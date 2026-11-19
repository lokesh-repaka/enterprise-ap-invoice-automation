import React from 'react';

export default function OverviewTab({ setActiveTab, onSelectInvoice, invoices = [] }) {
  // Fallback default sample invoices if backend empty or loading
  const defaultInvoices = [
    {
      id: 'INV-2026-9041',
      vendor: 'Acme Industrial Ltd.',
      date: 'Nov 18, 2026',
      amount: '$14,250.00',
      matchPct: 98.5,
      status: 'Requires Manager Approval (> $10k)',
      statusClass: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      actionLabel: 'Review',
      actionClass: 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm',
    },
    {
      id: 'INV-2026-9042',
      vendor: 'CloudScale Data Services',
      date: 'Nov 18, 2026',
      amount: '$3,420.50',
      matchPct: 96.2,
      status: 'Approved (Automated)',
      statusClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      actionLabel: 'View',
      actionClass: 'bg-slate-800 hover:bg-slate-700 text-slate-300',
    },
    {
      id: 'INV-2026-9043',
      vendor: 'Global Logistics Express',
      date: 'Nov 17, 2026',
      amount: '$890.00',
      matchPct: 78.0,
      status: 'Math Mismatch ($12.00)',
      statusClass: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      actionLabel: 'Resolve',
      actionClass: 'bg-amber-600 hover:bg-amber-500 text-white shadow-sm',
    },
  ];

  const displayList = invoices.length > 0 ? invoices : defaultInvoices;

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Invoice Processing Telemetry</h1>
        <p className="text-xs text-slate-400 mt-1">
          Real-time status across multi-modal extraction, business rule validation, and payment releases.
        </p>
      </div>

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1 */}
        <div className="bg-[#111827] rounded-2xl p-5 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Invoices Processed</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-xs">
              📊
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">1,482</span>
            <span className="text-[11px] font-semibold text-emerald-400">↑ 12.4%</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">$4,821,390 volume (MTD)</p>
        </div>

        {/* Card 2 */}
        <div className="bg-[#111827] rounded-2xl p-5 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Automated Match Rate</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold text-xs">
              ⚡
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">92.6%</span>
            <span className="text-[11px] font-semibold text-emerald-400">↑ 3.1%</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Straight-through processing</p>
        </div>

        {/* Card 3 */}
        <div className="bg-[#111827] rounded-2xl p-5 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Action Required</span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold text-xs">
              ⚠️
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">3</span>
            <span className="text-[11px] font-semibold text-amber-400">1 Critical</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Pending review or approval</p>
        </div>

        {/* Card 4 */}
        <div className="bg-[#111827] rounded-2xl p-5 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Average Processing Speed</span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center font-bold text-xs">
              ⏱️
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">1.8s</span>
            <span className="text-[11px] font-semibold text-emerald-400">99.4% accuracy</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Automated AI extraction</p>
        </div>
      </div>

      {/* Recent Invoices Table */}
      <div className="bg-[#111827] rounded-2xl border border-slate-800 overflow-hidden shadow-sm">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-sm text-white">Recent Invoices</h2>
            <p className="text-xs text-slate-400">Real-time status of incoming vendor invoices</p>
          </div>
          <button
            onClick={() => setActiveTab('exceptions')}
            className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
          >
            View Action Queue →
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/20 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="p-3.5 pl-6">Invoice ID</th>
                <th className="p-3.5">Vendor</th>
                <th className="p-3.5">Invoice Date</th>
                <th className="p-3.5">Total Amount</th>
                <th className="p-3.5">Extraction Match</th>
                <th className="p-3.5">Current Status</th>
                <th className="p-3.5 pr-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {displayList.map((inv) => (
                <tr key={inv.id} className="hover:bg-slate-800/30 transition">
                  <td className="p-3.5 pl-6 font-mono text-indigo-400 font-semibold">{inv.id}</td>
                  <td className="p-3.5 text-white font-medium">{inv.vendor}</td>
                  <td className="p-3.5 text-slate-300">{inv.date}</td>
                  <td className="p-3.5 font-semibold text-white">{inv.amount}</td>
                  <td className="p-3.5">
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div
                          className={`h-full ${inv.matchPct < 85 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                          style={{ width: `${inv.matchPct}%` }}
                        ></div>
                      </div>
                      <span className={`font-mono text-[11px] ${inv.matchPct < 85 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {inv.matchPct}%
                      </span>
                    </div>
                  </td>
                  <td className="p-3.5">
                    <span className={`px-2.5 py-1 rounded-full text-[10px] font-semibold border ${inv.statusClass}`}>
                      {inv.status}
                    </span>
                  </td>
                  <td className="p-3.5 pr-6 text-right">
                    <button
                      onClick={() => onSelectInvoice(inv.id)}
                      className={`px-3 py-1 rounded-lg text-xs font-medium transition ${inv.actionClass}`}
                    >
                      {inv.actionLabel || 'Review'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

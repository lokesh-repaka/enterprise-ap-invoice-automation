import React from 'react';

export default function ExceptionsTab({ onSelectInvoice }) {
  const exceptions = [
    {
      id: 'INV-2026-9043',
      vendor: 'Global Logistics Express',
      issue: 'Total Amount Discrepancy ($12.00)',
      description: 'Sum of extracted items ($878.00) does not match invoice total ($890.00).',
      received: '2 hours ago',
      assigned: 'Sarah Jenkins',
      severity: 'danger',
      icon: '⚠️',
      buttonLabel: 'Review & Fix',
      buttonClass: 'bg-indigo-600 hover:bg-indigo-500 text-white',
    },
    {
      id: 'INV-2026-9041',
      vendor: 'Acme Industrial Ltd.',
      issue: 'Approval Required (> $10,000)',
      description: 'Invoice amount is $14,250.00. Requires Finance Manager sign-off.',
      received: '4 hours ago',
      assigned: 'Michael Chang (Finance Manager)',
      severity: 'warning',
      icon: '💰',
      buttonLabel: 'Approve',
      buttonClass: 'bg-amber-600 hover:bg-amber-500 text-white',
    },
  ];

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Action Required</h1>
        <p className="text-xs text-slate-400 mt-1">
          Invoices flagged for discrepancies or requiring manager approval before payment can be released.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {exceptions.map((item) => (
          <div
            key={item.id}
            className={`bg-[#111827] rounded-2xl p-4 border ${
              item.severity === 'danger'
                ? 'border-rose-500/30 hover:border-rose-500/50'
                : 'border-amber-500/30 hover:border-amber-500/50'
            } shadow-md flex items-center justify-between transition`}
          >
            <div className="flex items-start gap-4">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-base mt-0.5 ${
                  item.severity === 'danger'
                    ? 'bg-rose-500/10 text-rose-400'
                    : 'bg-amber-500/10 text-amber-400'
                }`}
              >
                {item.icon}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-indigo-400">{item.id}</span>
                  <span className="text-white font-semibold text-xs">{item.vendor}</span>
                  <span
                    className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                      item.severity === 'danger'
                        ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                        : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                    }`}
                  >
                    {item.issue}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">{item.description}</p>
                <div className="flex items-center gap-4 text-[11px] text-slate-500 mt-2">
                  <span>Received: {item.received}</span>
                  <span>Assigned: {item.assigned}</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => onSelectInvoice(item.id)}
              className={`px-4 py-2 rounded-xl text-xs font-semibold shadow transition ${item.buttonClass}`}
            >
              {item.buttonLabel}
            </button>
          </div>
        ))}
      </div>
    </section>
  );
}

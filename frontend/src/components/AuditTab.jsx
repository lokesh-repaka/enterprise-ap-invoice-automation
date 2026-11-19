import React from 'react';

export default function AuditTab() {
  const events = [
    {
      id: 1,
      dotClass: 'bg-emerald-500',
      title: 'Invoice Automatically Approved',
      time: '10 mins ago',
      description: 'INV-2026-9042 matched PO-44102 and passed all tax checks. Released for payment.',
      meta: 'Action by: Automated Verification System',
    },
    {
      id: 2,
      dotClass: 'bg-amber-500',
      title: 'Manager Approval Requested',
      time: '4 hours ago',
      description: 'INV-2026-9041 ($14,250.00) routed to Michael Chang (Finance Manager).',
      meta: 'Reason: High-value invoice exceeding $10,000 threshold',
    },
    {
      id: 3,
      dotClass: 'bg-blue-500',
      title: 'Invoice Uploaded & Archived',
      time: '4 hours ago',
      description: 'Acme_Invoice_9041.pdf received and stored in secure digital archive.',
      meta: 'Uploaded by: Sarah Jenkins (AP Specialist)',
    },
  ];

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Compliance & Audit Trail</h1>
        <p className="text-xs text-slate-400 mt-1">
          Chronological record of invoice approvals, adjustments, and system verifications.
        </p>
      </div>

      <div className="bg-[#111827] rounded-2xl p-6 border border-slate-800 shadow-sm">
        <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {events.map((evt) => (
            <div key={evt.id} className="relative">
              <span
                className={`absolute -left-6 top-1 w-3.5 h-3.5 rounded-full ${evt.dotClass} border-2 border-slate-900`}
              ></span>
              <div className="text-xs">
                <span className="font-bold text-white">{evt.title}</span>
                <span className="text-[10px] text-slate-400 ml-2">{evt.time}</span>
                <p className="text-slate-300 mt-0.5">{evt.description}</p>
                <div className="mt-1 text-[10px] text-slate-500">{evt.meta}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}


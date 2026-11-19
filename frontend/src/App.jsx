import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import LandingPage from './components/LandingPage';
import OverviewTab from './components/OverviewTab';
import UploadTab from './components/UploadTab';
import WorkbenchTab from './components/WorkbenchTab';
import ExceptionsTab from './components/ExceptionsTab';
import AuditTab from './components/AuditTab';
import { checkHealth, loginPersona, listInvoices } from './api';

const PERSONAS = [
  {
    username: 'sarah.clerk',
    name: 'Sarah Jenkins',
    role: 'ap_clerk',
    roleTitle: 'AP Specialist',
    description: 'AP Specialist (Scan & Verify)',
    avatar: 'SJ',
    badgeClass: 'bg-purple-500/20 text-purple-400',
  },
  {
    username: 'michael.manager',
    name: 'Michael Chang',
    role: 'finance_manager',
    roleTitle: 'Finance Manager',
    description: 'Finance Manager (Approve > $10K)',
    avatar: 'MC',
    badgeClass: 'bg-blue-500/20 text-blue-400',
  },
  {
    username: 'dave.admin',
    name: 'Dave Miller',
    role: 'system_admin',
    roleTitle: 'Internal Auditor',
    description: 'Internal Audit & Compliance',
    avatar: 'DM',
    badgeClass: 'bg-emerald-500/20 text-emerald-400',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState(() => {
    const hash = window.location.hash.replace('#', '');
    return hash && hash !== 'landing' ? hash : 'landing';
  });
  const [selectedInvoiceId, setSelectedInvoiceId] = useState('INV-2026-9041');
  const [currentUser, setCurrentUser] = useState(PERSONAS[0]);
  const [systemStatus, setSystemStatus] = useState({ status: 'healthy' });

  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash.replace('#', '');
      if (hash) {
        setActiveTab(hash);
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  const [invoices, setInvoices] = useState([
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
  ]);

  // Initial authentication & health check
  useEffect(() => {
    checkHealth().then(setSystemStatus).catch(() => {});
    loginPersona(currentUser.username).catch((err) => {
      console.warn('Initial persona login warning:', err);
    });
  }, []);

  // When persona changes, acquire fresh JWT token
  const handleUserChange = (persona) => {
    setCurrentUser(persona);
    loginPersona(persona.username).catch((err) => {
      console.warn('Persona switch warning:', err);
    });
  };

  const handleSelectInvoice = (invId) => {
    setSelectedInvoiceId(invId);
    setActiveTab('workbench');
  };

  const handleInvoiceUploaded = (newInvoice) => {
    setInvoices((prev) => [newInvoice, ...prev]);
    setSelectedInvoiceId(newInvoice.id);
  };

  const handleInvoiceAction = (invId, action) => {
    setInvoices((prev) =>
      prev.map((inv) =>
        inv.id === invId
          ? {
              ...inv,
              status: action === 'Approved' ? 'Approved for Payment' : 'Rejected',
              statusClass:
                action === 'Approved'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/20',
              actionLabel: 'View',
              actionClass: 'bg-slate-800 hover:bg-slate-700 text-slate-300',
            }
          : inv
      )
    );
  };

  if (activeTab === 'landing') {
    return (
      <LandingPage
        onLaunchWorkbench={() => {
          setActiveTab('dashboard');
          window.location.hash = 'dashboard';
        }}
      />
    );
  }

  return (
    <div className="bg-[#0b0f19] text-[#f1f5f9] antialiased m-0 p-0 font-sans text-sm selection:bg-indigo-500 selection:text-white flex h-screen overflow-hidden">
      {/* Left Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentUser={currentUser}
        setCurrentUser={handleUserChange}
        personas={PERSONAS}
        systemStatus={systemStatus}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <Header activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Scrollable Viewport */}
        <main className="flex-1 overflow-y-auto p-8 space-y-6">
          {activeTab === 'dashboard' && (
            <OverviewTab
              setActiveTab={setActiveTab}
              onSelectInvoice={handleSelectInvoice}
              invoices={invoices}
            />
          )}

          {activeTab === 'upload' && (
            <UploadTab
              setActiveTab={setActiveTab}
              onInvoiceUploaded={handleInvoiceUploaded}
            />
          )}

          {activeTab === 'workbench' && (
            <WorkbenchTab
              selectedInvoiceId={selectedInvoiceId}
              currentUser={currentUser}
              setActiveTab={setActiveTab}
              onInvoiceAction={handleInvoiceAction}
            />
          )}

          {activeTab === 'exceptions' && (
            <ExceptionsTab onSelectInvoice={handleSelectInvoice} />
          )}

          {activeTab === 'audit' && <AuditTab />}
        </main>
      </div>
    </div>
  );
}


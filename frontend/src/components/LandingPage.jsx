import React from 'react';
import { Shield, Sparkles, ArrowRight, ExternalLink, Cpu, CheckCircle2, Lock, FileText, Database, Layers, Check } from 'lucide-react';

export default function LandingPage({ onLaunchWorkbench }) {
  return (
    <div className="bg-[#0f172a] text-slate-100 antialiased selection:bg-blue-600 selection:text-white min-h-screen">
      
      {/* ================= TOP NAVIGATION BAR ================= */}
      <nav className="sticky top-0 z-50 backdrop-blur-xl bg-slate-900/85 border-b border-slate-800/80 px-6 py-3.5 transition-all">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          
          {/* Brand & Status */}
          <div className="flex items-center gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-400 flex items-center justify-center text-white shadow-lg shadow-blue-500/30">
              <Shield className="w-6 h-6 stroke-[2.3]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-extrabold tracking-tight text-white">Apex<span className="text-blue-400">AP</span> Enterprise</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  Azure East US 2 Live
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">Autonomous Multi-Modal Invoice Intelligence</p>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="hidden md:flex items-center gap-6 text-xs font-semibold text-slate-300">
            <a href="#about" className="hover:text-blue-400 transition-colors">What It Is</a>
            <a href="#problem" className="hover:text-blue-400 transition-colors">The Challenge</a>
            <a href="#solution" className="hover:text-blue-400 transition-colors">How It Works</a>
            <a href="#kpis" className="hover:text-blue-400 transition-colors">Pilot Metrics</a>
            <a href="#architecture" className="hover:text-blue-400 transition-colors">Detailed Blueprint</a>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3">
            <button
              onClick={onLaunchWorkbench}
              className="group px-4 py-2 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-500 shadow-lg shadow-blue-500/25 border border-blue-400/30 transition-all flex items-center gap-2 transform active:scale-95 cursor-pointer"
            >
              <span>🚀 Launch Application Workbench</span>
              <ArrowRight className="w-3.5 h-3.5 transform group-hover:translate-x-1 transition-transform" />
            </button>
          </div>

        </div>
      </nav>

      {/* ================= HERO SECTION ================= */}
      <header id="about" className="relative pt-16 pb-20 overflow-hidden border-b border-slate-800/80 bg-gradient-to-b from-slate-900 via-slate-900 to-[#0f172a]">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[350px] bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute top-1/3 left-1/4 w-[400px] h-[250px] bg-indigo-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="max-w-7xl mx-auto px-6 relative z-10">
          
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold mb-6">
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            <span>Version 0.1.0 Ready • 100% Offline Pytest Suite (755 Passed) • 90.00% STP</span>
          </div>

          <h1 className="text-4xl lg:text-6xl font-extrabold tracking-tight text-white max-w-4xl leading-[1.15]">
            Autonomous Accounts Payable Intelligence for <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">Global Enterprises</span>
          </h1>

          <p className="mt-6 text-lg text-slate-300 max-w-3xl leading-relaxed">
            <strong>ApexAP Enterprise</strong> is an AI-powered Accounts Payable automation system engineered for high-volume multinational finance operations across <strong>US, UK, Germany, and Spain</strong>. It captures complex multi-format vendor invoices, extracts header and line-item financial data via dual-tier AI vision, deterministically enforces line-by-line arithmetic and multi-country tax rules, and routes validated payments with zero manual intervention.
          </p>

          {/* CTA Row */}
          <div className="mt-8 flex flex-wrap items-center gap-4">
            <button
              onClick={onLaunchWorkbench}
              className="px-6 py-3.5 rounded-2xl text-sm font-bold text-white bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-500 shadow-xl shadow-blue-500/30 border border-blue-400/40 transition-all flex items-center gap-2.5 transform active:scale-95 cursor-pointer"
            >
              <span>🚀 Launch Application Workbench</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <a
              href="#architecture"
              className="px-6 py-3.5 rounded-2xl text-sm font-semibold text-slate-200 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 transition flex items-center gap-2"
            >
              <span>View Detailed System Blueprint</span>
              <span className="text-slate-400">↓</span>
            </a>
          </div>

          {/* KPI Strip */}
          <div id="kpis" className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-2xl bg-slate-800/60 border border-slate-700/70 backdrop-blur-sm">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Straight-Through Processing</p>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-emerald-400 font-mono">90.00%</span>
                <span className="text-[11px] text-emerald-300 font-medium">Target: ≥ 65%</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Touchless payment release on 300 pilot invoices</p>
            </div>

            <div className="p-4 rounded-2xl bg-slate-800/60 border border-slate-700/70 backdrop-blur-sm">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Mathematical Determinism</p>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-blue-400 font-mono">±$0.02</span>
                <span className="text-[11px] text-blue-300 font-medium">Zero Hallucinations</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Pure Python arithmetic verification on all line totals</p>
            </div>

            <div className="p-4 rounded-2xl bg-slate-800/60 border border-slate-700/70 backdrop-blur-sm">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Turnaround Latency</p>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-cyan-400 font-mono">716 ms</span>
                <span className="text-[11px] text-cyan-300 font-medium">Full 300 Batch</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Instant classification, model routing, & tax audit</p>
            </div>

            <div className="p-4 rounded-2xl bg-slate-800/60 border border-slate-700/70 backdrop-blur-sm">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Regulatory Hold</p>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-3xl font-extrabold text-purple-400 font-mono">7 Years</span>
                <span className="text-[11px] text-purple-300 font-medium">2,557 Days</span>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Hardware-enforced Azure Blob WORM immutable storage</p>
            </div>
          </div>

        </div>
      </header>

      {/* ================= THE PROBLEM SECTION ================= */}
      <section id="problem" className="py-16 border-b border-slate-800/80 bg-[#0d1527]">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-3xl">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wider uppercase bg-rose-500/10 text-rose-400 border border-rose-500/20">The Business Problem</span>
            <h2 className="text-3xl font-extrabold tracking-tight text-white mt-3">Why Traditional Accounts Payable Is Broken</h2>
            <p className="text-slate-400 mt-2 text-sm leading-relaxed">
              Finance departments process millions of invoices yearly using error-prone manual data entry or naive LLM wrappers that hallucinate math and fail regulatory audits.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mt-10">
            <div className="p-5 rounded-2xl bg-slate-900/90 border border-rose-900/30 hover:border-rose-500/40 transition-colors space-y-2.5">
              <div className="w-9 h-9 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center font-bold text-sm">⏱️</div>
              <h3 className="text-sm font-bold text-white">Manual Data Entry & Backlogs</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                AP specialists spend <strong>$12 to $15 per invoice</strong> manually re-typing line items. Turnaround cycles take 7 to 14 days, creating month-end bottlenecks and missed vendor early-payment discounts.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/90 border border-amber-900/30 hover:border-amber-500/40 transition-colors space-y-2.5">
              <div className="w-9 h-9 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center font-bold text-sm">🧮</div>
              <h3 className="text-sm font-bold text-white">LLM Arithmetic Hallucinations</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Raw Generative AI models struggle with financial precision: they hallucinate totals, miscalculate quantity × price, and silently produce rounding errors that violate general ledger accounting principles.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/90 border border-cyan-900/30 hover:border-cyan-500/40 transition-colors space-y-2.5">
              <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center font-bold text-sm">🌍</div>
              <h3 className="text-sm font-bold text-white">Cross-Border Tax Non-Compliance</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Managing distinct tax regimes—US State/County Sales Tax, UK VAT (20%), German MwSt (19%/7%), and Spanish IVA (21%/10%)—leads to costly tax compliance violations and rejected foreign deductions.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/90 border border-purple-900/30 hover:border-purple-500/40 transition-colors space-y-2.5">
              <div className="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center justify-center font-bold text-sm">🛡️</div>
              <h3 className="text-sm font-bold text-white">Duplicate Fraud & Audit Vulnerability</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                3.6% of invoices contain duplicate submissions or altered totals. Without 7-year legally binding immutable records (WORM) and tamper-proof event logs, companies risk failing SOX and IRS compliance audits.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ================= THE SOLUTION SECTION ================= */}
      <section id="solution" className="py-16 border-b border-slate-800/80 bg-slate-900/50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="max-w-3xl">
            <span className="px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">The ApexAP Solution</span>
            <h2 className="text-3xl font-extrabold tracking-tight text-white mt-3">Deterministic AI + Pure Rule Enforcement</h2>
            <p className="text-slate-400 mt-2 text-sm leading-relaxed">
              We separate extraction from validation: LLMs read unstructured documents, while pure Python code executes strict financial arithmetic and compliance checks.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mt-10">
            <div className="p-5 rounded-2xl bg-slate-900 border border-emerald-500/20 hover:border-emerald-500/40 transition space-y-2">
              <span className="text-xs font-bold text-emerald-400">01 • Multi-Modal Routing</span>
              <h4 className="text-sm font-bold text-white">PyMuPDF Text Density</h4>
              <p className="text-xs text-slate-400">Automatically routes searchable PDFs to fast GPT-4o-mini and raster scans to GPT-4o Vision, cutting extraction token costs by 68%.</p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900 border border-blue-500/20 hover:border-blue-500/40 transition space-y-2">
              <span className="text-xs font-bold text-blue-400">02 • Zero-Tolerance Math</span>
              <h4 className="text-sm font-bold text-white">±$0.02 Python Validation</h4>
              <p className="text-xs text-slate-400">Deterministic code checks quantity × price = line total, subtotal + tax = total, and cross-checks against country tax brackets.</p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900 border border-indigo-500/20 hover:border-indigo-500/40 transition space-y-2">
              <span className="text-xs font-bold text-indigo-400">03 • Tri-Tier Router</span>
              <h4 className="text-sm font-bold text-white">90% Straight-Through Flow</h4>
              <p className="text-xs text-slate-400">≥90% confidence + balanced math auto-approves. Discrepancies route to AP Specialists; invoices &gt; $10,000 route to Finance Managers.</p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900 border border-purple-500/20 hover:border-purple-500/40 transition space-y-2">
              <span className="text-xs font-bold text-purple-400">04 • Regulatory Sealing</span>
              <h4 className="text-sm font-bold text-white">7-Year Immutable WORM</h4>
              <p className="text-xs text-slate-400">Inbound documents sealed in Azure Blob with a 2,557-day immutable retention policy and SHA-256 duplicate fingerprinting.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ================= DETAILED ARCHITECTURAL BLUEPRINT ================= */}
      <section id="architecture" className="py-16 bg-[#0b1220]">
        <div className="max-w-[1520px] mx-auto px-6 space-y-6">

          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
            <div>
              <span className="px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wider uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20">System Blueprint</span>
              <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">Enterprise Architecture Infographic & Workflow</h2>
              <p className="text-xs text-slate-400 mt-0.5">Strict East US 2 Data Confinement • Keyless Entra ID Managed Identity • Zero Public Data Egress</p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={onLaunchWorkbench}
                className="px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 shadow-md shadow-blue-500/20 border border-blue-400/30 transition flex items-center gap-2 cursor-pointer"
              >
                <span>🚀 Launch Application Workbench</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Blueprint White Card */}
          <div className="bg-white text-[#1e293b] rounded-3xl border border-slate-300 shadow-2xl p-7 space-y-6">
            
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div className="flex items-center gap-4">
                <div className="w-11 h-11 rounded-2xl bg-gradient-to-tr from-blue-600 via-indigo-600 to-cyan-500 flex items-center justify-center text-white shadow-md">
                  <Shield className="w-6 h-6 stroke-[2.2]" />
                </div>
                <div>
                  <div className="flex items-center gap-2.5">
                    <h3 className="text-xl font-extrabold tracking-tight text-slate-900">Enterprise AP Invoice Automation <span className="text-blue-600">– Detailed Architecture</span></h3>
                    <span className="px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wider uppercase bg-blue-100 text-blue-700 border border-blue-200">East US 2 Production</span>
                  </div>
                  <p className="text-xs text-slate-500 font-medium mt-0.5">
                    AI-Powered Invoice Processing with Multi-Modal Extraction, Deterministic Rules Engine, 3-Way Match & Azure East US 2 Confinement
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500 bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-xl">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                <span>Version 0.1.0 • High Availability • Keyless Entra ID</span>
              </div>
            </div>

            {/* 3-Column Section */}
            <div className="grid grid-cols-12 gap-5 items-start">
              
              {/* Left Column: Personas & Capabilities */}
              <div className="col-span-3 space-y-4">
                <div className="bg-gradient-to-b from-blue-50/80 to-white rounded-2xl border border-blue-200/80 p-4 shadow-sm">
                  <div className="flex items-center gap-2 text-blue-800 font-bold text-xs uppercase tracking-wider mb-3">
                    <span className="w-5 h-5 rounded-lg bg-blue-600 text-white flex items-center justify-center text-[10px]">👥</span>
                    <span>Users & Personas</span>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-start gap-2.5 p-2 rounded-xl bg-white border border-blue-100 shadow-2xs">
                      <div className="w-7 h-7 rounded-lg bg-purple-100 text-purple-700 font-bold text-xs flex items-center justify-center flex-shrink-0">SJ</div>
                      <div>
                        <p className="text-xs font-bold text-slate-800">Sarah Jenkins</p>
                        <p className="text-[10px] text-purple-700 font-medium">AP Specialist (Scan & Verify)</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">Invoice Upload, Line-Item Reconciliation, Mismatch Triage</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5 p-2 rounded-xl bg-white border border-blue-100 shadow-2xs">
                      <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-700 font-bold text-xs flex items-center justify-center flex-shrink-0">MC</div>
                      <div>
                        <p className="text-xs font-bold text-slate-800">Michael Chang</p>
                        <p className="text-[10px] text-blue-700 font-medium">Finance Manager (Approve &gt; $10K)</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">High-Value Sign-off, Budget & PO Variance Escalations</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5 p-2 rounded-xl bg-white border border-blue-100 shadow-2xs">
                      <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-700 font-bold text-xs flex items-center justify-center flex-shrink-0">DM</div>
                      <div>
                        <p className="text-xs font-bold text-slate-800">Dave Miller</p>
                        <p className="text-[10px] text-emerald-700 font-medium">Internal Audit & Compliance Admin</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">7-Year WORM Audit Trail, Security & RBAC Guardrails</p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-gradient-to-b from-indigo-50/80 to-white rounded-2xl border border-indigo-200/80 p-4 shadow-sm space-y-2.5">
                  <div className="flex items-center gap-2 text-indigo-900 font-bold text-xs uppercase tracking-wider mb-2">
                    <span className="w-5 h-5 rounded-lg bg-indigo-600 text-white flex items-center justify-center text-[10px]">⚡</span>
                    <span>Key Platform Capabilities</span>
                  </div>
                  <ul className="text-[11px] text-slate-700 space-y-2">
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Multi-Modal AI Capture:</strong> PyMuPDF density checks to route Searchable PDF vs Scans.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Model Gateway:</strong> Dynamic routing to GPT-4o-mini or GPT-4o Vision with caching.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Deterministic Rules:</strong> Line arithmetic (±$0.02) & invoice total (±$0.05) checks.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Multi-Country Tax:</strong> US Sales Tax, UK VAT, German MwSt, and Spanish IVA.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Tri-Tier Routing:</strong> ≥90% STP, 80-89% Review, &lt;80% Approval, &gt;$10k Sign-off.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>7-Year WORM Storage:</strong> 2,557 days immutable Azure Blob retention hold.</div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-3.5 h-3.5 text-indigo-600 mt-0.5 flex-shrink-0" />
                      <div><strong>Modern React UI:</strong> Client-facing Workbench with Zoom, Exceptions, & Audit.</div>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Center Column: Workflow & Backend */}
              <div className="col-span-6 space-y-4">
                <div className="bg-white rounded-2xl border border-slate-300 p-4 shadow-sm">
                  <div className="flex items-center justify-between border-b border-slate-100 pb-2 mb-3">
                    <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider text-slate-800">
                      <span className="w-5 h-5 rounded-lg bg-blue-600 text-white flex items-center justify-center text-[10px]">💻</span>
                      <span>Application Layer (User Interaction)</span>
                    </div>
                    <span className="text-[10px] font-mono text-indigo-600 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-md font-semibold">React 18 • Vite 5 • Tailwind CSS</span>
                  </div>

                  <div className="grid grid-cols-12 gap-3 items-center">
                    <div className="col-span-5 bg-slate-900 rounded-xl p-3 text-white border border-slate-800 shadow">
                      <div className="flex items-center gap-1.5 mb-2">
                        <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                        <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                        <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                        <span className="text-[9px] font-mono text-slate-400 ml-1">ApexAP Review Workbench</span>
                      </div>
                      <div className="bg-slate-950 p-2 rounded-lg text-[9px] space-y-1 font-mono">
                        <div className="flex justify-between text-indigo-400"><span>INV-2026-9041</span><span>$14,250.00</span></div>
                        <div className="text-slate-400">Match: 98.5% • Balanced ✓</div>
                        <div className="text-amber-400 bg-amber-500/10 px-1 py-0.5 rounded text-[8px]">Needs Manager Approval</div>
                      </div>
                    </div>

                    <div className="col-span-7 grid grid-cols-2 gap-1.5 text-[10px] text-slate-700">
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Executive Dashboard</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Interactive Zoom (+/-)</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Drag & Drop Ingestion</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>3-Way Match Verification</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Exceptions Triage Queue</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Role Switcher (JWT)</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Revalidate with Reason</span></div>
                      <div className="flex items-center gap-1.5"><span className="text-emerald-600 font-bold">✓</span> <span>Chronological Audit Trail</span></div>
                    </div>
                  </div>
                </div>

                {/* Core Workflow Card */}
                <div className="bg-gradient-to-b from-purple-50/60 to-white rounded-2xl border-2 border-purple-200 p-4 shadow-sm space-y-3">
                  <div className="flex items-center justify-between border-b border-purple-100 pb-2">
                    <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider text-purple-900">
                      <span className="w-5 h-5 rounded-lg bg-purple-600 text-white flex items-center justify-center text-[10px]">⚙️</span>
                      <span>Extraction, Validation Rules & Confidence Routing</span>
                    </div>
                    <span className="text-[10px] font-mono text-purple-700 bg-purple-100 border border-purple-200 px-2 py-0.5 rounded font-semibold">10-State FSM • Zero Hallucination Risk</span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div className="grid grid-cols-12 gap-2 items-center">
                      <div className="col-span-3 bg-white p-2 rounded-xl border border-purple-200 text-center shadow-2xs">
                        <span className="text-[10px] font-bold text-purple-900">Document Classifier</span>
                        <p className="text-[9px] text-slate-500">PyMuPDF Text Density Check</p>
                      </div>
                      <div className="col-span-1 text-center font-bold text-slate-400">➔</div>
                      <div className="col-span-4 bg-white p-2 rounded-xl border border-purple-200 text-center shadow-2xs">
                        <span className="text-[10px] font-bold text-purple-900">Model Gateway Router</span>
                        <p className="text-[9px] text-slate-500">GPT-4o-mini (PDF) / GPT-4o (Vision)</p>
                      </div>
                      <div className="col-span-1 text-center font-bold text-slate-400">➔</div>
                      <div className="col-span-3 bg-white p-2 rounded-xl border border-purple-200 text-center shadow-2xs">
                        <span className="text-[10px] font-bold text-purple-900">Pydantic Parser</span>
                        <p className="text-[9px] text-slate-500">10 Header Fields + Line Items</p>
                      </div>
                    </div>

                    <div className="bg-white p-3 rounded-xl border border-slate-200 shadow-2xs space-y-1.5">
                      <div className="flex items-center justify-between text-[11px] font-bold text-slate-800">
                        <span>Deterministic Rules Engine (Pure Python — Never Trusts LLM Math)</span>
                        <span className="text-emerald-600 font-mono text-[10px]">100% Math Verification</span>
                      </div>
                      <div className="grid grid-cols-4 gap-2 text-[10px]">
                        <div className="p-1.5 bg-slate-50 rounded-lg border border-slate-200 text-center">
                          <strong>Duplicate SHA-256</strong>
                          <p className="text-[9px] text-slate-500">Vendor + Inv# + Total</p>
                        </div>
                        <div className="p-1.5 bg-slate-50 rounded-lg border border-slate-200 text-center">
                          <strong>Line Arithmetic</strong>
                          <p className="text-[9px] text-slate-500">Qty × Unit = Total ±$0.02</p>
                        </div>
                        <div className="p-1.5 bg-slate-50 rounded-lg border border-slate-200 text-center">
                          <strong>Total Arithmetic</strong>
                          <p className="text-[9px] text-slate-500">Sub + Tax = Total ±$0.05</p>
                        </div>
                        <div className="p-1.5 bg-slate-50 rounded-lg border border-slate-200 text-center">
                          <strong>Multi-Country Tax</strong>
                          <p className="text-[9px] text-slate-500">US, UK, DE, ES Schemes</p>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                      <div className="p-2.5 rounded-xl bg-emerald-50 border border-emerald-300">
                        <div className="font-bold text-emerald-800">≥90% Confidence + Balanced</div>
                        <div className="font-mono text-emerald-700 font-bold text-xs mt-0.5">VALIDATED (STP)</div>
                        <p className="text-[9px] text-emerald-600 mt-1">90% Straight-Through Released</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-300">
                        <div className="font-bold text-amber-800">80% – 89% or Minor Flag</div>
                        <div className="font-mono text-amber-700 font-bold text-xs mt-0.5">REQUIRES_REVIEW</div>
                        <p className="text-[9px] text-amber-600 mt-1">Routed to Sarah (AP Specialist)</p>
                      </div>
                      <div className="p-2.5 rounded-xl bg-rose-50 border border-rose-300">
                        <div className="font-bold text-rose-800">&lt;80% or Total &gt; $10k</div>
                        <div className="font-mono text-rose-700 font-bold text-xs mt-0.5">MANAGER_APPROVAL</div>
                        <p className="text-[9px] text-rose-600 mt-1">Escalated to Michael Chang</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Right Column: Ingestion Pipeline */}
              <div className="col-span-3 space-y-4">
                <div className="bg-gradient-to-b from-cyan-50/80 to-white rounded-2xl border border-cyan-200 p-4 shadow-sm space-y-3">
                  <div className="flex items-center gap-2 text-cyan-900 font-bold text-xs uppercase tracking-wider mb-2">
                    <span className="w-5 h-5 rounded-lg bg-cyan-600 text-white flex items-center justify-center text-[10px]">📦</span>
                    <span>Data Ingestion Pipeline</span>
                  </div>

                  <div className="space-y-2.5">
                    <div className="p-2.5 bg-white rounded-xl border border-cyan-100 shadow-2xs">
                      <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span className="text-cyan-600">📄</span> Inbound Documents
                      </span>
                      <p className="text-[10px] text-slate-500 mt-0.5">Single/batch PDF, PNG, JPG, XLSX (up to 25 MB max size cap, FR-01).</p>
                    </div>

                    <div className="p-2.5 bg-white rounded-xl border border-cyan-100 shadow-2xs">
                      <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span className="text-cyan-600">🔍</span> Document Classifier
                      </span>
                      <p className="text-[10px] text-slate-500 mt-0.5">PyMuPDF text-layer analysis distinguishes searchable PDFs from scans.</p>
                    </div>

                    <div className="p-2.5 bg-white rounded-xl border border-cyan-100 shadow-2xs">
                      <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span className="text-cyan-600">🛡️</span> 7-Year WORM Storage
                      </span>
                      <p className="text-[10px] text-slate-500 mt-0.5">Stored in Azure Blob container <code className="font-mono text-cyan-700 bg-cyan-50 px-1 rounded">raw-invoices-immutable</code> (2,557 days hold).</p>
                    </div>

                    <div className="p-2.5 bg-white rounded-xl border border-cyan-100 shadow-2xs">
                      <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span className="text-cyan-600">🏢</span> Vendor Master DB
                      </span>
                      <p className="text-[10px] text-slate-500 mt-0.5">15 enterprise vendors, tax schemes, currency, and date locale resolution.</p>
                    </div>

                    <div className="p-2.5 bg-white rounded-xl border border-cyan-100 shadow-2xs">
                      <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                        <span className="text-cyan-600">💱</span> ECB Exchange Rates
                      </span>
                      <p className="text-[10px] text-slate-500 mt-0.5">Daily EUR/GBP/USD FX rates with fallback tolerance checks.</p>
                    </div>
                  </div>
                </div>
              </div>

            </div>

            {/* Horizontal Services Bar */}
            <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-4 text-white shadow-md border border-slate-800">
              <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider text-slate-300">
                  <span className="text-indigo-400">🗄️</span>
                  <span>Data & AI Services Layer (Keyless Azure Managed Identity Integration)</span>
                </div>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 border border-cyan-800 px-2 py-0.5 rounded font-semibold">ADR-007 Zero Static Secrets</span>
              </div>

              <div className="grid grid-cols-5 gap-3 text-center text-xs">
                <div className="p-3 bg-slate-850/80 rounded-xl border border-slate-700/80">
                  <div className="text-lg">🗄️</div>
                  <strong className="text-white text-[11px] block mt-1">Azure SQL / SQLite</strong>
                  <p className="text-[9px] text-slate-400 mt-0.5">Vendors, Invoices, Lines, AuditLogs</p>
                </div>

                <div className="p-3 bg-slate-850/80 rounded-xl border border-slate-700/80">
                  <div className="text-lg">📦</div>
                  <strong className="text-white text-[11px] block mt-1">Azure Blob (7-Yr WORM)</strong>
                  <p className="text-[9px] text-slate-400 mt-0.5">2,557 days immutable retention policy</p>
                </div>

                <div className="p-3 bg-slate-850/80 rounded-xl border border-slate-700/80">
                  <div className="text-lg">⚡</div>
                  <strong className="text-white text-[11px] block mt-1">Azure Cache for Redis</strong>
                  <p className="text-[9px] text-slate-400 mt-0.5">Rate limiter & background job queue</p>
                </div>

                <div className="p-3 bg-slate-850/80 rounded-xl border border-slate-700/80">
                  <div className="text-lg">🧠</div>
                  <strong className="text-white text-[11px] block mt-1">Azure OpenAI East US 2</strong>
                  <p className="text-[9px] text-slate-400 mt-0.5">GPT-4o Vision & GPT-4o-mini</p>
                </div>

                <div className="p-3 bg-slate-850/80 rounded-xl border border-slate-700/80">
                  <div className="text-lg">🔐</div>
                  <strong className="text-white text-[11px] block mt-1">Azure Key Vault</strong>
                  <p className="text-[9px] text-slate-400 mt-0.5">Hardware-backed secrets with Entra ID</p>
                </div>
              </div>
            </div>

            {/* Lifecycle Strip */}
            <div className="bg-slate-900 rounded-2xl p-4 text-white shadow-lg border border-slate-800">
              <div className="flex items-center gap-2 font-bold text-xs uppercase tracking-wider text-slate-300 mb-3">
                <span className="text-blue-400">🚀</span>
                <span>End-to-End Invoice Processing Lifecycle (7 Verified Stages)</span>
              </div>

              <div className="grid grid-cols-7 gap-2 text-center">
                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">1</div>
                  <strong className="text-[10px] text-white block">Upload Invoice</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">Vendor/Clerk submits via React Web UI</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">2</div>
                  <strong className="text-[10px] text-white block">WORM Archiving</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">SHA-256 dedup & 7-yr immutable Blob write</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">3</div>
                  <strong className="text-[10px] text-white block">AI Model Gateway</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">Routes to GPT-4o Vision or GPT-4o-mini</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">4</div>
                  <strong className="text-[10px] text-white block">Pydantic Parsing</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">Extracts 10 headers & all line items</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">5</div>
                  <strong className="text-[10px] text-white block">Rules Engine</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">Line math ±$0.02 & tax (US/UK/DE/ES)</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-blue-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">6</div>
                  <strong className="text-[10px] text-white block">Confidence Routing</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">≥90% STP vs Review vs Manager ($10k)</p>
                </div>

                <div className="bg-slate-800/90 p-2.5 rounded-xl border border-slate-700">
                  <div className="w-5 h-5 rounded-full bg-emerald-500 text-white text-[10px] font-bold mx-auto flex items-center justify-center mb-1">7</div>
                  <strong className="text-[10px] text-emerald-400 block">Payment Release</strong>
                  <p className="text-[8px] text-slate-400 mt-0.5">Immutable AuditLog written & payment queued</p>
                </div>
              </div>
            </div>

          </div>

        </div>
      </section>

      {/* ================= BOTTOM LAUNCH PAD ================= */}
      <section className="py-14 bg-gradient-to-r from-blue-900 via-indigo-900 to-slate-900 border-t border-blue-500/30 text-white">
        <div className="max-w-5xl mx-auto px-6 text-center space-y-5">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 text-blue-200 text-xs font-semibold">
            <span>⚡ Ready for Live Interactive Walkthrough</span>
          </div>
          <h2 className="text-3xl font-extrabold text-white">Experience the Live AP Review Workbench</h2>
          <p className="text-slate-300 text-sm max-w-2xl mx-auto leading-relaxed">
            Test document ingestion with sample PDFs, zoom in/out with the document viewer, verify line arithmetic, and simulate multi-role approvals with Sarah, Michael, and Dave.
          </p>
          <div className="pt-2 flex flex-wrap items-center justify-center gap-4">
            <button
              onClick={onLaunchWorkbench}
              className="px-8 py-4 rounded-2xl text-base font-extrabold text-slate-900 bg-white hover:bg-slate-100 shadow-2xl transition transform hover:-translate-y-0.5 active:scale-95 flex items-center gap-2.5 cursor-pointer"
            >
              <span>🚀 Go to Application Workbench</span>
              <ArrowRight className="w-5 h-5 text-blue-600" />
            </button>
          </div>
        </div>
      </section>

      {/* ================= FOOTER ================= */}
      <footer className="py-8 bg-slate-950 border-t border-slate-900 text-slate-500 text-xs">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="font-bold text-slate-300">ApexAP Enterprise</span>
            <span>•</span>
            <span>Confined to Azure East US 2</span>
            <span>•</span>
            <span>7-Year WORM Regulatory Compliance</span>
          </div>
          <div className="flex items-center gap-6">
            <button onClick={onLaunchWorkbench} className="hover:text-blue-400 transition cursor-pointer">
              Workbench UI
            </button>
            <a href="https://github.com/lokesh-repaka/enterprise-ap-invoice-automation" target="_blank" rel="noopener noreferrer" className="hover:text-blue-400 transition">
              GitHub Repo
            </a>
          </div>
        </div>
      </footer>

    </div>
  );
}


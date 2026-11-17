-- ==============================================================================
-- Enterprise AP Invoice Automation Platform — Authoritative Database Schema DDL
-- Specification: CLAUDE.md §6 and LLD §3
-- Compatibility: SQLite 3 (local development) and Azure SQL Server (production)
-- ==============================================================================

-- 1. Vendors Master Table
CREATE TABLE IF NOT EXISTS vendors (
    vendor_tax_id VARCHAR(50) PRIMARY KEY,
    vendor_id VARCHAR(50) NULL,
    vendor_name VARCHAR(200) NOT NULL,
    country_code VARCHAR(10) NOT NULL,
    date_format_locale VARCHAR(20) NOT NULL DEFAULT 'MM/DD/YYYY',
    number_format_preference VARCHAR(20) NOT NULL DEFAULT 'PERIOD',
    default_currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    tax_scheme VARCHAR(100) NULL,
    standard_tax_rate DECIMAL(5, 4) NOT NULL DEFAULT 0.0000,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS IX_vendors_vendor_id ON vendors (vendor_id);
CREATE INDEX IF NOT EXISTS IX_vendors_country ON vendors (country_code);

-- 2. Core Invoices Table
CREATE TABLE IF NOT EXISTS invoices (
    invoice_id VARCHAR(36) PRIMARY KEY,
    vendor_tax_id VARCHAR(50) NOT NULL,
    vendor_name VARCHAR(200) NULL,
    invoice_number VARCHAR(100) NOT NULL,
    invoice_date DATE NULL,
    due_date DATE NULL,
    po_number VARCHAR(100) NULL,
    subtotal DECIMAL(18, 2) NULL,
    total_tax_amount DECIMAL(18, 2) NULL,
    total_amount DECIMAL(18, 2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    total_amount_usd DECIMAL(18, 2) NULL,
    confidence_macro_avg DECIMAL(5, 2) NOT NULL DEFAULT 0.00,
    status VARCHAR(50) NOT NULL DEFAULT 'UPLOADED',
    composite_hash VARCHAR(64) NOT NULL,
    blob_raw_url VARCHAR(500) NULL,
    blob_json_url VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_tax_id) REFERENCES vendors (vendor_tax_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS IX_invoices_composite_hash ON invoices (composite_hash);
CREATE INDEX IF NOT EXISTS IX_invoices_status_date ON invoices (status, invoice_date);
CREATE INDEX IF NOT EXISTS IX_invoices_vendor_number ON invoices (vendor_tax_id, invoice_number);
CREATE INDEX IF NOT EXISTS IX_invoices_po_number ON invoices (po_number);

-- 3. Invoice Lines Breakdown Table
CREATE TABLE IF NOT EXISTS invoice_lines (
    line_id VARCHAR(36) PRIMARY KEY,
    invoice_id VARCHAR(36) NOT NULL,
    line_number INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity DECIMAL(18, 4) NOT NULL,
    unit_price DECIMAL(18, 4) NOT NULL,
    line_total DECIMAL(18, 2) NOT NULL,
    line_tax_rate DECIMAL(5, 4) NOT NULL DEFAULT 0.0000,
    confidence_score DECIMAL(5, 2) NULL DEFAULT 100.00,
    FOREIGN KEY (invoice_id) REFERENCES invoices (invoice_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS IX_invoice_lines_invoice_num ON invoice_lines (invoice_id, line_number);

-- 4. Immutable Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id VARCHAR(36) PRIMARY KEY,
    invoice_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    field_name VARCHAR(100) NULL,
    previous_value TEXT NULL,
    new_value TEXT NULL,
    reason_code VARCHAR(100) NULL,
    comment VARCHAR(1000) NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (invoice_id) REFERENCES invoices (invoice_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS IX_audit_logs_invoice_timestamp ON audit_logs (invoice_id, timestamp);
CREATE INDEX IF NOT EXISTS IX_audit_logs_user_id ON audit_logs (user_id);

-- 5. Daily ECB Exchange Rates Table
CREATE TABLE IF NOT EXISTS exchange_rates (
    rate_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rate_date DATE NOT NULL,
    from_currency VARCHAR(10) NOT NULL,
    to_currency VARCHAR(10) NOT NULL DEFAULT 'USD',
    exchange_rate DECIMAL(18, 6) NOT NULL,
    CONSTRAINT UQ_exchange_rates UNIQUE (rate_date, from_currency, to_currency)
);

CREATE INDEX IF NOT EXISTS IX_exchange_rates_lookup ON exchange_rates (rate_date, from_currency);

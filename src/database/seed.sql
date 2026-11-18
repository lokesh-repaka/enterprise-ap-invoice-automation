-- ==============================================================================
-- Enterprise AP Invoice Automation Platform — Idempotent Seed Script
-- Specification: CLAUDE.md §5 & §6 (15 Vendors across 4 Jurisdictions + ECB FX)
-- ==============================================================================

-- 1. Seed Vendor Master (15 vendors: 5 US, 4 DE, 3 ES, 3 GB)
INSERT OR IGNORE INTO vendors (
    vendor_tax_id, vendor_id, vendor_name, country_code,
    date_format_locale, number_format_preference, default_currency,
    tax_scheme, standard_tax_rate, is_active
) VALUES
    ('US-12-3456789', 'VEND-1001', 'Apex Global Logistics Inc', 'US', 'MM/DD/YYYY', 'PERIOD', 'USD', 'Sales Tax (8%)', 0.0800, 1),
    ('US-98-7654321', 'VEND-1002', 'CyberCore Solutions LLC', 'US', 'MM/DD/YYYY', 'PERIOD', 'USD', 'Sales Tax (8.25%)', 0.0825, 1),
    ('US-45-8921345', 'VEND-1003', 'Precision Machine Parts Co', 'US', 'MM/DD/YYYY', 'PERIOD', 'USD', 'Sales Tax (7%)', 0.0700, 1),
    ('US-33-2198745', 'VEND-1004', 'BlueRidge Cloud Services', 'US', 'MM/DD/YYYY', 'PERIOD', 'USD', 'Sales Tax (0% / Exempt)', 0.0000, 1),
    ('US-77-6543210', 'VEND-1005', 'OmniPackaging Direct', 'US', 'MM/DD/YYYY', 'PERIOD', 'USD', 'Sales Tax (8.25%)', 0.0825, 1),
    ('DE123456789', 'VEND-2001', 'Bavaria Werkzeuge GmbH', 'DE', 'DD/MM/YYYY', 'COMMA', 'EUR', 'MwSt (19%)', 0.1900, 1),
    ('DE987654321', 'VEND-2002', 'Nordic Sensorik AG', 'DE', 'DD/MM/YYYY', 'COMMA', 'EUR', 'MwSt (19%)', 0.1900, 1),
    ('DE456123789', 'VEND-2003', 'Berlin Druck & Medien KG', 'DE', 'DD/MM/YYYY', 'COMMA', 'EUR', 'MwSt (7%)', 0.0700, 1),
    ('DE321654987', 'VEND-2004', 'Hanseatic Spedition GmbH', 'DE', 'DD/MM/YYYY', 'COMMA', 'EUR', 'MwSt (19%)', 0.1900, 1),
    ('ESB12345678', 'VEND-3001', 'Iberia Componentes Industriales SL', 'ES', 'DD/MM/YYYY', 'COMMA', 'EUR', 'IVA (21%)', 0.2100, 1),
    ('ESA98765432', 'VEND-3002', 'Mediterraneo Quimica SA', 'ES', 'DD/MM/YYYY', 'COMMA', 'EUR', 'IVA (21%)', 0.2100, 1),
    ('ESB45678912', 'VEND-3003', 'Castilla Logistica Integral SL', 'ES', 'DD/MM/YYYY', 'COMMA', 'EUR', 'IVA (10%)', 0.1000, 1),
    ('GB123456789', 'VEND-4001', 'Thames River Tech Solutions Ltd', 'GB', 'DD/MM/YYYY', 'PERIOD', 'GBP', 'VAT (20%)', 0.2000, 1),
    ('GB987654321', 'VEND-4002', 'Caledonian Heavy Freight Ltd', 'GB', 'DD/MM/YYYY', 'PERIOD', 'GBP', 'VAT (20%)', 0.2000, 1),
    ('GB555666777', 'VEND-4003', 'Albion Safety Supplies Ltd', 'GB', 'DD/MM/YYYY', 'PERIOD', 'GBP', 'VAT (20%)', 0.2000, 1);

-- 2. Seed Daily ECB Exchange Rates
INSERT OR IGNORE INTO exchange_rates (rate_date, from_currency, to_currency, exchange_rate) VALUES
    ('2026-02-15', 'EUR', 'USD', 1.085000),
    ('2026-02-15', 'GBP', 'USD', 1.272000),
    ('2026-02-15', 'USD', 'USD', 1.000000);

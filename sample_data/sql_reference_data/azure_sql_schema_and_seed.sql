
-- 1. Vendor Master Table
CREATE TABLE dbo.VendorMaster (
    VendorID NVARCHAR(50) PRIMARY KEY,
    VendorName NVARCHAR(200) NOT NULL,
    TaxID_VAT NVARCHAR(50) NOT NULL,
    CountryCode NVARCHAR(10) NOT NULL,
    DateLocalePreference NVARCHAR(20) NOT NULL,
    NumberFormatPreference NVARCHAR(10) NOT NULL,
    DefaultCurrency NVARCHAR(10) NOT NULL,
    StandardTaxRate DECIMAL(5,4) NOT NULL
);

-- 2. Daily Exchange Rates
CREATE TABLE dbo.ExchangeRates_ECB (
    RateID INT IDENTITY(1,1) PRIMARY KEY,
    RateDate DATE NOT NULL,
    FromCurrency NVARCHAR(10) NOT NULL,
    ToCurrency NVARCHAR(10) NOT NULL,
    ExchangeRate DECIMAL(18,6) NOT NULL
);

-- 3. Purchase Orders Table
CREATE TABLE dbo.PurchaseOrders (
    PONumber NVARCHAR(50) PRIMARY KEY,
    VendorID NVARCHAR(50) NOT NULL,
    POApprovedTotal DECIMAL(18,2) NOT NULL,
    Currency NVARCHAR(10) NOT NULL
);

-- 4. Standard Tax Rates Table
CREATE TABLE dbo.TaxRules (
    RuleID INT IDENTITY(1,1) PRIMARY KEY,
    CountryCode NVARCHAR(10) NOT NULL,
    TaxType NVARCHAR(50) NOT NULL,
    ApplicableRate DECIMAL(5,4) NOT NULL
);

-- 5. Core Invoices Table (Matches LLD §2 & CLAUDE.md §6)
CREATE TABLE dbo.Invoices (
    InvoiceID NVARCHAR(50) PRIMARY KEY,
    InvoiceNumber NVARCHAR(50) NOT NULL,
    CompositeHash NVARCHAR(64) NOT NULL UNIQUE,
    VendorID NVARCHAR(50) NULL,
    VendorName NVARCHAR(200) NULL,
    InvoiceDate DATE NULL,
    DueDate DATE NULL,
    PONumber NVARCHAR(50) NULL,
    Subtotal DECIMAL(18,2) NULL,
    TaxAmount DECIMAL(18,2) NULL,
    TotalAmount DECIMAL(18,2) NULL,
    Currency NVARCHAR(10) NULL,
    Status NVARCHAR(50) NOT NULL,
    ConfidenceScore DECIMAL(5,2) NULL,
    RawBlobURL NVARCHAR(500) NULL,
    CreatedTimestamp DATETIME DEFAULT GETUTCDATE()
);

const API_BASE = '';

let authToken = null;

export const setAuthToken = (token) => {
  authToken = token;
};

export const getAuthToken = () => authToken;

const getHeaders = (isJson = true) => {
  const headers = {};
  if (isJson) {
    headers['Content-Type'] = 'application/json';
  }
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  return headers;
};

export const checkHealth = async () => {
  try {
    const res = await fetch(`${API_BASE}/health`);
    return await res.json();
  } catch (err) {
    return { status: 'offline' };
  }
};

export const getDemoPersonas = async () => {
  try {
    const res = await fetch(`${API_BASE}/api/v1/demo/personas`);
    if (!res.ok) throw new Error('Failed to fetch personas');
    return await res.json();
  } catch (err) {
    return {
      personas: [
        { username: 'sarah.clerk', name: 'Sarah Jenkins', role: 'ap_clerk' },
        { username: 'michael.manager', name: 'Michael Chang', role: 'finance_manager' },
        { username: 'dave.admin', name: 'Dave Miller', role: 'system_admin' },
      ],
    };
  }
};

export const loginPersona = async (username) => {
  const res = await fetch(`${API_BASE}/api/v1/demo/token?persona=${encodeURIComponent(username)}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Authentication failed');
  const data = await res.json();
  setAuthToken(data.access_token);
  return data;
};

export const listInvoices = async () => {
  const res = await fetch(`${API_BASE}/api/v1/invoices`, {
    headers: getHeaders(),
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.items || data;
};

export const getInvoiceDetail = async (id) => {
  const res = await fetch(`${API_BASE}/api/v1/invoices/${encodeURIComponent(id)}`, {
    headers: getHeaders(),
  });
  if (!res.ok) throw new Error('Invoice not found');
  return await res.json();
};

export const uploadInvoice = async (file, vendorId = 'UNKNOWN') => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('vendor_id', vendorId);

  const res = await fetch(`${API_BASE}/api/v1/invoices/upload`, {
    method: 'POST',
    headers: getHeaders(false),
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Upload failed');
  }
  return await res.json();
};

export const getExceptionsQueue = async () => {
  const res = await fetch(`${API_BASE}/api/v1/invoices/exceptions`, {
    headers: getHeaders(),
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.items || data;
};

export const approveInvoice = async (id, comment = 'Approved via Workbench') => {
  const res = await fetch(`${API_BASE}/api/v1/invoices/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ comment }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Approval failed');
  }
  return await res.json();
};

export const rejectInvoice = async (id, reason) => {
  const res = await fetch(`${API_BASE}/api/v1/invoices/${encodeURIComponent(id)}/reject`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'Rejection failed');
  }
  return await res.json();
};

export const getAuditTrail = async (id) => {
  const res = await fetch(`${API_BASE}/api/v1/invoices/${encodeURIComponent(id)}/audit`, {
    headers: getHeaders(),
  });
  if (!res.ok) return [];
  return await res.json();
};


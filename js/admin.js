/**
 * Company AI — Admin Module
 * Handles admin panel: User Management, Audit Trail, Knowledge Vault
 */

(function () {
  'use strict';

  // ============================================================================
  // Configuration & State
  // ============================================================================

  const API_BASE = '';
  let currentTab = 'users';
  let usersData = [];
  let auditData = [];
  let vaultData = [];
  let auditFilter = '';

  // ============================================================================
  // DOM References
  // ============================================================================

  const adminModal = document.getElementById('admin-modal');
  const adminCloseBtn = document.getElementById('admin-modal-close-btn');
  const adminTabBtns = document.querySelectorAll('.admin-tab-btn');
  const adminTabPanels = document.querySelectorAll('.admin-tab-panel');

  // Users tab
  const usersBody = document.getElementById('admin-users-body');

  // Audit tab
  const auditSearch = document.getElementById('admin-audit-search');
  const auditBody = document.getElementById('admin-audit-body');

  // Vault tab
  const vaultFile = document.getElementById('vault-file');
  const vaultFileName = document.getElementById('vault-file-name');
  const vaultDept = document.getElementById('vault-dept');
  const vaultLevel = document.getElementById('vault-level');
  const vaultCompany = document.getElementById('vault-company');
  const vaultIngestForm = document.getElementById('vault-ingest-form');
  const vaultIngestBtn = document.getElementById('vault-ingest-btn');
  const vaultBody = document.getElementById('admin-vault-body');

  // ============================================================================
  // API Helpers
  // ============================================================================

  async function apiRequest(endpoint, options = {}) {
    const token = Auth.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  // ============================================================================
  // Tab Management
  // ============================================================================

  function switchTab(tabName) {
    currentTab = tabName;

    adminTabBtns.forEach(btn => {
      const isActive = btn.dataset.adminTab === tabName;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', isActive);
    });

    adminTabPanels.forEach(panel => {
      const isActive = panel.id === `admin-tab-${tabName}`;
      panel.classList.toggle('hidden', !isActive);
      if (isActive) panel.setAttribute('aria-hidden', 'false');
      else panel.setAttribute('aria-hidden', 'true');
    });

    // Load data for the tab
    if (tabName === 'users') loadUsers();
    else if (tabName === 'audit') loadAudit();
    else if (tabName === 'vault') loadVault();
  }

  // ============================================================================
  // User Management
  // ============================================================================

  async function loadUsers() {
    if (!usersBody) return;
    usersBody.innerHTML = '<tr><td colspan="5" class="loading-cell"><div class="spinner"></div>Loading users...</td></tr>';

    try {
      usersData = await apiRequest('/admin/users');
      renderUsers();
    } catch (err) {
      console.error('Failed to load users:', err);
      usersBody.innerHTML = `<tr><td colspan="5" class="error-cell">Failed to load users: ${err.message}</td></tr>`;
    }
  }

  function renderUsers() {
    if (!usersBody) return;

    if (!usersData.length) {
      usersBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No users found</td></tr>';
      return;
    }

    usersBody.innerHTML = usersData.map(user => `
      <tr data-user-id="${user.id}">
        <td>${escapeHtml(user.email)}</td>
        <td>
          <select class="role-select" data-user-id="${user.id}" ${user.id === Auth.getUser()?.id ? 'disabled' : ''}>
            <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
            <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
          </select>
        </td>
        <td>
          <span class="status-badge ${user.is_active ? 'active' : 'inactive'}">
            ${user.is_active ? 'Active' : 'Inactive'}
          </span>
        </td>
        <td>${formatDate(user.created_at)}</td>
        <td>
          <div class="action-buttons">
            <button class="btn-icon btn-toggle" data-action="toggle" data-user-id="${user.id}"
                    aria-label="${user.is_active ? 'Deactivate' : 'Activate'} ${escapeHtml(user.email)}"
                    ${user.id === Auth.getUser()?.id ? 'disabled' : ''}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                ${user.is_active
                  ? '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'
                  : '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/><path d="M8 12l2 2 4-4"/>'}
              </svg>
            </button>
            <button class="btn-icon btn-delete" data-action="delete" data-user-id="${user.id}"
                    aria-label="Delete ${escapeHtml(user.email)}"
                    ${user.id === Auth.getUser()?.id ? 'disabled' : ''}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
              </svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

    // Bind action handlers
    usersBody.querySelectorAll('.role-select').forEach(select => {
      select.addEventListener('change', e => {
        updateUserRole(e.target.dataset.userId, e.target.value);
      });
    });

    usersBody.querySelectorAll('[data-action="toggle"]').forEach(btn => {
      btn.addEventListener('click', e => {
        const userId = btn.dataset.userId;
        const user = usersData.find(u => u.id === userId);
        if (user) toggleUserStatus(userId, !user.is_active);
      });
    });

    usersBody.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.addEventListener('click', e => {
        const userId = btn.dataset.userId;
        const user = usersData.find(u => u.id === userId);
        if (user && confirm(`Delete user ${user.email}? This cannot be undone.`)) {
          deleteUser(userId);
        }
      });
    });
  }

  async function updateUserRole(userId, role) {
    try {
      await apiRequest(`/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role })
      });
      UI.showToast('Role updated', 'success');
      loadUsers();
    } catch (err) {
      console.error('Failed to update role:', err);
      UI.showToast('Failed to update role', 'error');
      loadUsers(); // Revert UI
    }
  }

  async function toggleUserStatus(userId, isActive) {
    try {
      await apiRequest(`/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_active: isActive })
      });
      UI.showToast(`User ${isActive ? 'activated' : 'deactivated'}`, 'success');
      loadUsers();
    } catch (err) {
      console.error('Failed to toggle status:', err);
      UI.showToast('Failed to update status', 'error');
      loadUsers();
    }
  }

  async function deleteUser(userId) {
    try {
      await apiRequest(`/admin/users/${userId}`, { method: 'DELETE' });
      UI.showToast('User deleted', 'success');
      loadUsers();
    } catch (err) {
      console.error('Failed to delete user:', err);
      UI.showToast('Failed to delete user', 'error');
    }
  }

  // ============================================================================
  // Audit Trail
  // ============================================================================

  async function loadAudit() {
    if (!auditBody) return;
    auditBody.innerHTML = '<tr><td colspan="5" class="loading-cell"><div class="spinner"></div>Loading audit logs...</td></tr>';

    try {
      auditData = await apiRequest('/admin/audit');
      renderAudit();
    } catch (err) {
      console.error('Failed to load audit:', err);
      auditBody.innerHTML = `<tr><td colspan="5" class="error-cell">Failed to load audit logs: ${err.message}</td></tr>`;
    }
  }

  function renderAudit() {
    if (!auditBody) return;

    let filtered = auditData;
    if (auditFilter) {
      const filter = auditFilter.toLowerCase();
      filtered = auditData.filter(entry =>
        entry.action?.toLowerCase().includes(filter) ||
        entry.user_email?.toLowerCase().includes(filter) ||
        entry.ip_address?.toLowerCase().includes(filter) ||
        JSON.stringify(entry.details || {}).toLowerCase().includes(filter)
      );
    }

    if (!filtered.length) {
      auditBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No audit logs found</td></tr>';
      return;
    }

    auditBody.innerHTML = filtered.map(entry => `
      <tr>
        <td>${formatDateTime(entry.created_at)}</td>
        <td><span class="action-badge">${escapeHtml(entry.action)}</span></td>
        <td>${escapeHtml(entry.user_email || 'System')}</td>
        <td>${escapeHtml(entry.ip_address || '—')}</td>
        <td class="details-cell">
          <details>
            <summary>View details</summary>
            <pre>${escapeHtml(JSON.stringify(entry.details || {}, null, 2))}</pre>
          </details>
        </td>
      </tr>
    `).join('');
  }

  function handleAuditSearch(e) {
    auditFilter = e.target.value.trim();
    UI.debounce(renderAudit, 300)();
  }

  // ============================================================================
  // Knowledge Vault
  // ============================================================================

  async function loadVault() {
    if (!vaultBody) return;
    vaultBody.innerHTML = '<tr><td colspan="5" class="loading-cell"><div class="spinner"></div>Loading documents...</td></tr>';

    try {
      vaultData = await apiRequest('/admin/documents');
      renderVault();
    } catch (err) {
      console.error('Failed to load vault:', err);
      vaultBody.innerHTML = `<tr><td colspan="5" class="error-cell">Failed to load documents: ${err.message}</td></tr>`;
    }
  }

  function renderVault() {
    if (!vaultBody) return;

    if (!vaultData.length) {
      vaultBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No documents in vault</td></tr>';
      return;
    }

    vaultBody.innerHTML = vaultData.map(doc => `
      <tr data-doc-id="${doc.id}">
        <td>${escapeHtml(doc.filename)}</td>
        <td><span class="dept-badge">${escapeHtml(doc.department)}</span></td>
        <td><span class="level-badge level-${doc.access_level}">Level ${doc.access_level}</span></td>
        <td>${formatDate(doc.created_at)}</td>
        <td>
          <button class="btn-icon btn-delete" data-action="delete" data-doc-id="${doc.id}"
                  aria-label="Delete ${escapeHtml(doc.filename)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
            </svg>
          </button>
        </td>
      </tr>
    `).join('');

    vaultBody.querySelectorAll('[data-action="delete"]').forEach(btn => {
      btn.addEventListener('click', e => {
        const docId = btn.dataset.docId;
        const doc = vaultData.find(d => d.id === docId);
        if (doc && confirm(`Delete document "${doc.filename}"?`)) {
          deleteDocument(docId);
        }
      });
    });
  }

  async function ingestDocument(formData) {
    try {
      UI.setButtonLoading(vaultIngestBtn, true);

      const file = formData.get('file');
      const company_id = formData.get('company_id') || Auth.getUser()?.company_id;
      const department = formData.get('department');
      const min_access_level = parseInt(formData.get('access_level'), 10);

      if (!company_id) {
        throw new Error('Company ID is required');
      }

      // Read file content
      const text = await file.text();

      // Simple chunking by paragraphs (split on double newline)
      const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0);
      const chunks = paragraphs.map(p => ({ content: p.trim() }));

      const payload = {
        company_id,
        filename: file.name,
        department,
        min_access_level,
        chunks
      };

      const res = await fetch(`${API_BASE}/admin/documents/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${Auth.getToken()}`
        },
        body: JSON.stringify(payload)
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

      UI.showToast('Document ingested successfully', 'success');
      vaultIngestForm.reset();
      vaultFileName.textContent = 'No file selected';
      loadVault();
    } catch (err) {
      console.error('Failed to ingest document:', err);
      UI.showToast(err.message || 'Failed to ingest document', 'error');
    } finally {
      UI.setButtonLoading(vaultIngestBtn, false);
    }
  }

  async function deleteDocument(docId) {
    try {
      await apiRequest(`/admin/documents/${docId}`, { method: 'DELETE' });
      UI.showToast('Document deleted', 'success');
      loadVault();
    } catch (err) {
      console.error('Failed to delete document:', err);
      UI.showToast('Failed to delete document', 'error');
    }
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  function handleTabClick(e) {
    const tabName = e.currentTarget.dataset.adminTab;
    if (tabName) switchTab(tabName);
  }

  function handleFileSelect(e) {
    const file = e.target.files[0];
    vaultFileName.textContent = file ? file.name : 'No file selected';
  }

  function handleVaultIngest(e) {
    e.preventDefault();

    const file = vaultFile.files[0];
    if (!file) {
      UI.showToast('Please select a file', 'warning');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('department', vaultDept.value);
    formData.append('access_level', vaultLevel.value);
    if (vaultCompany.value.trim()) formData.append('company_id', vaultCompany.value.trim());

    ingestDocument(formData);
  }

  function handleAdminClose() {
    UI.closeModal(adminModal);
  }

  // ============================================================================
  // Helpers
  // ============================================================================

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString([], {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    // Tab switching
    adminTabBtns.forEach(btn => btn.addEventListener('click', handleTabClick));
    adminCloseBtn?.addEventListener('click', handleAdminClose);

    // Vault form
    vaultFile?.addEventListener('change', handleFileSelect);
    vaultIngestForm?.addEventListener('submit', handleVaultIngest);

    // Audit search
    auditSearch?.addEventListener('input', handleAuditSearch);

    // Close modal on overlay click
    adminModal?.addEventListener('click', e => {
      if (e.target === adminModal) handleAdminClose();
    });
  }

  // ============================================================================
  // Public API
  // ============================================================================

  window.Admin = {
    init,
    open: () => UI.openModal(adminModal),
    close: () => UI.closeModal(adminModal),
    switchTab,
    loadUsers,
    loadAudit,
    loadVault,
    apiRequest
  };

  // Auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
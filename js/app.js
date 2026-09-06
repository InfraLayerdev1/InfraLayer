/**
 * Company AI — Main Application Entry Point
 * Initializes all modules and handles global app state
 */

(function () {
  'use strict';

  // ============================================================================
  // Global State
  // ============================================================================

  let isInitialized = false;

  // ============================================================================
  // DOM References
  // ============================================================================

  const adminPanelBtn = document.getElementById('admin-panel-btn');
  const authModal = document.getElementById('auth-modal');
  const adminModal = document.getElementById('admin-modal');

  // ============================================================================
  // Initialization
  // ============================================================================

  async function init() {
    if (isInitialized) return;
    isInitialized = true;

    console.log('[Company AI] Initializing application...');

    // Initialize modules in order
    // UI initializes automatically (theme)
    // Auth initializes automatically (session restore)

    // Wait for auth to complete session verification
    await waitForAuth();

    // Initialize chat if authenticated
    if (Auth.isAuthenticated()) {
      Chat.init();
    }

    // Bind global event handlers
    bindGlobalEvents();

    // Handle admin panel button
    adminPanelBtn?.addEventListener('click', () => {
      if (Auth.isAdmin()) {
        Admin.open();
        Admin.loadUsers();
      } else {
        UI.showToast('Admin access required', 'warning');
      }
    });

    console.log('[Company AI] Application ready');
    UI.showToast('Welcome to Company AI', 'success', 2000);
  }

  function waitForAuth() {
    return new Promise(resolve => {
      // Check if auth has already initialized
      if (typeof Auth !== 'undefined' && Auth.getUser() !== undefined) {
        // Give auth a moment to complete verifyToken if needed
        setTimeout(resolve, 100);
      } else {
        // Wait for auth to be ready
        const checkAuth = setInterval(() => {
          if (typeof Auth !== 'undefined' && Auth.getUser() !== undefined) {
            clearInterval(checkAuth);
            setTimeout(resolve, 100);
          }
        }, 50);
      }
    });
  }

  function bindGlobalEvents() {
    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
      // Cmd/Ctrl + K: Focus search
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.getElementById('search-input');
        searchInput?.focus();
      }

      // Cmd/Ctrl + N: New chat
      if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
        e.preventDefault();
        if (Auth.isAuthenticated()) Chat.createSession();
      }

      // Cmd/Ctrl + /: Toggle theme
      if ((e.metaKey || e.ctrlKey) && e.key === '/') {
        e.preventDefault();
        UI.toggleTheme();
      }

      // Escape: Close modals (handled in ui.js)
    });

    // Handle auth state changes
    window.addEventListener('storage', e => {
      if (e.key === 'company-ai:token' || e.key === 'company-ai:user') {
        // Token changed in another tab - reload
        window.location.reload();
      }
    });

    // Network status
    window.addEventListener('online', () => {
      UI.showToast('Connection restored', 'success');
      if (Auth.isAuthenticated()) Chat.loadSessions();
    });

    window.addEventListener('offline', () => {
      UI.showToast('Connection lost. Some features may be unavailable.', 'warning', 8000);
    });

    // Visibility change - re-verify token when tab becomes active
    document.addEventListener('visibilitychange', async () => {
      if (!document.hidden && Auth.isAuthenticated()) {
        const valid = await Auth.verifyToken();
        if (!valid) {
          Auth.logout();
        }
      }
    });
  }

  // ============================================================================
  // Public API
  // ============================================================================

  window.App = {
    init,
    isInitialized: () => isInitialized
  };

  // ============================================================================
  // Auto-initialize
  // ============================================================================

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
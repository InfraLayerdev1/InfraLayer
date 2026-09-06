/**
 * Company AI — Authentication Module
 * Handles login, signup, JWT token management, and session state
 */

(function () {
  'use strict';

  // ============================================================================
  // Configuration & State
  // ============================================================================

  const API_BASE = '';
  const TOKEN_KEY = 'company-ai:token';
  const USER_KEY = 'company-ai:user';

  let currentUser = null;
  let authMode = 'login'; // 'login' | 'signup'

  // ============================================================================
  // DOM References
  // ============================================================================

  const authModal = document.getElementById('auth-modal');
  const authForm = document.getElementById('auth-form');
  const authTitle = document.getElementById('modal-title');
  const authSubtitle = authModal?.querySelector('.modal-subtitle');
  const nameGroup = document.getElementById('name-group');
  const authName = document.getElementById('auth-name');
  const authEmail = document.getElementById('auth-email');
  const authPassword = document.getElementById('auth-password');
  const authSubmitBtn = document.getElementById('auth-submit-btn');
  const switchText = document.getElementById('switch-text');
  const switchBtn = document.getElementById('switch-btn');
  const userProfileBtn = document.getElementById('user-profile-btn');
  const userNameDisplay = document.getElementById('user-name-display');
  const userRoleDisplay = document.getElementById('user-role-display');
  const adminPanelBtn = document.getElementById('admin-panel-btn');

  // ============================================================================
  // Token Management
  // ============================================================================

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
  }

  function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
  }

  function getUser() {
    const stored = localStorage.getItem(USER_KEY);
    return stored ? JSON.parse(stored) : null;
  }

  function setUser(user) {
    currentUser = user;
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    updateUserUI();
  }

  function clearUser() {
    currentUser = null;
    localStorage.removeItem(USER_KEY);
    updateUserUI();
  }

  // ============================================================================
  // API Helpers
  // ============================================================================

  async function apiRequest(endpoint, options = {}) {
    const token = getToken();
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
  // Auth Operations
  // ============================================================================

  async function login(email, password) {
    const data = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    setToken(data.token);
    setUser(data.user);
    return data;
  }

  async function signup(name, email, password) {
    const data = await apiRequest('/auth/signup', {
      method: 'POST',
      body: JSON.stringify({ full_name: name, email, password })
    });
    setToken(data.token);
    setUser(data.user);
    return data;
  }

  async function verifyToken() {
    try {
      const data = await apiRequest('/auth/me');
      setUser(data.user);
      return true;
    } catch {
      return false;
    }
  }

  function logout() {
    clearToken();
    clearUser();
    UI.showToast('Logged out successfully', 'success');
    UI.openModal(authModal);
  }

  // ============================================================================
  // UI Updates
  // ============================================================================

  function updateUserUI() {
    if (currentUser) {
      userNameDisplay.textContent = currentUser.name || 'User';
      userRoleDisplay.textContent = currentUser.role || 'User';
      userProfileBtn.title = `Logged in as ${currentUser.email}`;
      userProfileBtn.setAttribute('aria-label', `Logged in as ${currentUser.email}. Click to log out.`);
      adminPanelBtn?.classList.toggle('hidden', currentUser.role !== 'admin');
    } else {
      userNameDisplay.textContent = 'User';
      userRoleDisplay.textContent = 'Role';
      userProfileBtn.title = 'Log in';
      userProfileBtn.setAttribute('aria-label', 'Log in');
      adminPanelBtn?.classList.add('hidden');
    }
  }

  function switchAuthMode(mode) {
    authMode = mode;
    const isLogin = mode === 'login';

    authTitle.textContent = isLogin ? 'Log In' : 'Create Account';
    authSubtitle.textContent = isLogin ? 'Access your knowledge workspace' : 'Join your company workspace';
    authSubmitBtn.textContent = isLogin ? 'Log In' : 'Create Account';
    nameGroup.classList.toggle('hidden', isLogin);
    authName.required = !isLogin;
    switchText.textContent = isLogin ? "Don't have an account?" : 'Already have an account?';
    switchBtn.textContent = isLogin ? 'Sign Up' : 'Log In';

    UI.clearFormErrors(authForm);
  }

  function setAuthLoading(loading) {
    UI.setButtonLoading(authSubmitBtn, loading);
    authForm.querySelectorAll('input').forEach(input => input.disabled = loading);
    switchBtn.disabled = loading;
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  async function handleSubmit(e) {
    e.preventDefault();
    UI.clearFormErrors(authForm);

    const email = authEmail.value.trim();
    const password = authPassword.value;

    if (!email || !password) {
      UI.showToast('Please fill in all required fields', 'error');
      return;
    }

    if (!isValidEmail(email)) {
      UI.setFormErrors(authForm, { email: 'Please enter a valid email address' });
      return;
    }

    if (authMode === 'signup') {
      const name = authName.value.trim();
      if (!name) {
        UI.setFormErrors(authForm, { name: 'Please enter your full name' });
        return;
      }
      if (password.length < 8) {
        UI.setFormErrors(authForm, { password: 'Password must be at least 8 characters' });
        return;
      }
    }

    setAuthLoading(true);

    try {
      if (authMode === 'login') {
        await login(email, password);
        UI.showToast('Welcome back!', 'success');
      } else {
        await signup(authName.value.trim(), email, password);
        UI.showToast('Account created successfully!', 'success');
      }
      UI.closeModal(authModal);
      authForm.reset();
      if (window.Chat) window.Chat.init();
    } catch (err) {
      console.error('Auth error:', err);
      if (err.status === 401) {
        UI.setFormErrors(authForm, { email: 'Invalid email or password' });
      } else if (err.status === 409) {
        UI.setFormErrors(authForm, { email: 'An account with this email already exists' });
      } else {
        UI.showToast(err.message || 'Authentication failed. Please try again.', 'error');
      }
    } finally {
      setAuthLoading(false);
    }
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function handleSwitchMode() {
    switchAuthMode(authMode === 'login' ? 'signup' : 'login');
  }

  function handleProfileClick() {
    if (currentUser) {
      logout();
    } else {
      switchAuthMode('login');
      UI.openModal(authModal);
    }
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    // Restore session
    const token = getToken();
    const user = getUser();
    if (token && user) {
      currentUser = user;
      updateUserUI();
      verifyToken().catch(() => logout());
    } else {
      updateUserUI();
    }

    // Bind events
    authForm?.addEventListener('submit', handleSubmit);
    switchBtn?.addEventListener('click', handleSwitchMode);
    userProfileBtn?.addEventListener('click', handleProfileClick);

    // Close modal handlers
    authModal?.querySelectorAll('[data-close]').forEach(btn => {
      btn.addEventListener('click', () => UI.closeModal(authModal));
    });
  }

  // ============================================================================
  // Public API
  // ============================================================================

  window.Auth = {
    init,
    login,
    signup,
    logout,
    getToken,
    getUser: () => currentUser,
    isAuthenticated: () => !!currentUser,
    isAdmin: () => currentUser?.role === 'admin',
    verifyToken,
    switchAuthMode,
    apiRequest
  };

  // Auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
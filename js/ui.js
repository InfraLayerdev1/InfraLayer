/**
 * Company AI — UI Utilities Module
 * Handles modals, toasts, theme switching, and core DOM helpers
 */

(function () {
  'use strict';

  // ============================================================================
  // DOM Utilities
  // ============================================================================

  const $ = (selector, ctx = document) => ctx.querySelector(selector);
  const $$ = (selector, ctx = document) => [...ctx.querySelectorAll(selector)];

  const createEl = (tag, attrs = {}, children = []) => {
    const el = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.entries(v).forEach(([dk, dv]) => el.dataset[dk] = dv);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else el.setAttribute(k, v);
    });
    children.forEach(c => el.append(c instanceof Node ? c : document.createTextNode(c)));
    return el;
  };

  // ============================================================================
  // Theme Management
  // ============================================================================

  const THEME_KEY = 'company-ai:theme';
  const root = document.documentElement;

  function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function getStoredTheme() {
    return localStorage.getItem(THEME_KEY);
  }

  function applyTheme(theme) {
    root.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
  }

  function initTheme() {
    const stored = getStoredTheme();
    const initial = stored || getSystemTheme();
    applyTheme(initial);
  }

  function toggleTheme() {
    const current = root.getAttribute('data-theme') || 'light';
    applyTheme(current === 'light' ? 'dark' : 'light');
  }

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
    if (!getStoredTheme()) applyTheme(e.matches ? 'dark' : 'light');
  });

  // ============================================================================
  // Modal System
  // ============================================================================

  const modalStack = [];

  function openModal(modalEl) {
    if (!modalEl) return;
    modalStack.push(modalEl);
    modalEl.classList.remove('hidden');
    modalEl.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    trapFocus(modalEl);
  }

  function closeModal(modalEl) {
    if (!modalEl) return;
    const idx = modalStack.indexOf(modalEl);
    if (idx > -1) modalStack.splice(idx, 1);
    modalEl.classList.add('hidden');
    modalEl.setAttribute('aria-hidden', 'true');
    if (modalStack.length === 0) document.body.style.overflow = '';
    restoreFocus(modalEl);
  }

  function closeTopModal() {
    if (modalStack.length) closeModal(modalStack[modalStack.length - 1]);
  }

  // Focus trapping for accessibility
  let lastFocusedEl = null;

  function trapFocus(modal) {
    lastFocusedEl = document.activeElement;
    const focusable = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    modal._keydownHandler = e => {
      if (e.key !== 'Tab') return;
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    };
    modal.addEventListener('keydown', modal._keydownHandler);
    first?.focus();
  }

  function restoreFocus(modal) {
    modal.removeEventListener('keydown', modal._keydownHandler);
    lastFocusedEl?.focus();
  }

  // Click overlay to close
  $$('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) closeModal(overlay);
    });
  });

  // ESC to close
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeTopModal();
  });

  // ============================================================================
  // Toast Notifications
  // ============================================================================

  const toastContainer = $('#toast-container');

  const toastIcons = {
    success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  };

  function showToast(message, type = 'info', duration = 4000) {
    if (!toastContainer) return;

    const toast = createEl('div', { class: `toast toast-${type}`, role: 'alert' }, [
      createEl('div', { class: 'toast-icon', innerHTML: toastIcons[type] || toastIcons.info }),
      createEl('div', { class: 'toast-message' }, message),
      createEl('button', { class: 'toast-close', 'aria-label': 'Dismiss', onclick: () => removeToast(toast) }, [
        createEl('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' }, [
          createEl('path', { d: 'M18 6 6 18M6 6l12 12' })
        ])
      ])
    ]);

    toastContainer.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));

    const timer = setTimeout(() => removeToast(toast), duration);
    toast.dataset.timer = timer;
  }

  function removeToast(toast) {
    if (!toast || toast.classList.contains('hiding')) return;
    toast.classList.add('hiding');
    clearTimeout(toast.dataset.timer);
    toast.addEventListener('transitionend', () => toast.remove(), { once: true });
  }

  // ============================================================================
  // Loading States
  // ============================================================================

  function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.dataset.originalText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner" aria-hidden="true"></span><span>Loading...</span>`;
    } else {
      btn.disabled = false;
      btn.innerHTML = btn.dataset.originalText || btn.innerHTML;
      delete btn.dataset.originalText;
    }
  }

  // ============================================================================
  // Form Helpers
  // ============================================================================

  function serializeForm(form) {
    const data = new FormData(form);
    const obj = {};
    data.forEach((v, k) => obj[k] = v);
    return obj;
  }

  function setFormErrors(form, errors) {
    clearFormErrors(form);
    Object.entries(errors).forEach(([field, message]) => {
      const input = form.querySelector(`[name="${field}"], #${field}`);
      if (!input) return;
      input.setAttribute('aria-invalid', 'true');
      input.setAttribute('aria-describedby', `${field}-error`);
      const errorEl = createEl('div', { class: 'form-error', id: `${field}-error`, role: 'alert' }, message);
      input.parentNode.appendChild(errorEl);
    });
  }

  function clearFormErrors(form) {
    $$('.form-error', form).forEach(el => el.remove());
    $$('[aria-invalid="true"]', form).forEach(el => {
      el.removeAttribute('aria-invalid');
      el.removeAttribute('aria-describedby');
    });
  }

  // ============================================================================
  // Debounce / Throttle
  // ============================================================================

  function debounce(fn, delay) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  function throttle(fn, limit) {
    let inThrottle;
    return (...args) => {
      if (!inThrottle) {
        fn.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  // ============================================================================
  // Animation Helpers
  // ============================================================================

  function animate(el, keyframes, options = {}) {
    const defaultOptions = { duration: 200, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', fill: 'forwards' };
    return el.animate(keyframes, { ...defaultOptions, ...options });
  }

  function fadeIn(el, duration = 200) {
    return animate(el, [{ opacity: 0 }, { opacity: 1 }], { duration });
  }

  function fadeOut(el, duration = 200) {
    return animate(el, [{ opacity: 1 }, { opacity: 0 }], { duration });
  }

  function slideIn(el, direction = 'up', duration = 200) {
    const transforms = {
      up: [{ transform: 'translateY(10px)', opacity: 0 }, { transform: 'translateY(0)', opacity: 1 }],
      down: [{ transform: 'translateY(-10px)', opacity: 0 }, { transform: 'translateY(0)', opacity: 1 }],
      left: [{ transform: 'translateX(10px)', opacity: 0 }, { transform: 'translateX(0)', opacity: 1 }],
      right: [{ transform: 'translateX(-10px)', opacity: 0 }, { transform: 'translateX(0)', opacity: 1 }]
    };
    return animate(el, transforms[direction], { duration });
  }

  // ============================================================================
  // Public API
  // ============================================================================

  window.UI = {
    $,
    $$,
    createEl,
    initTheme,
    toggleTheme,
    getTheme: () => root.getAttribute('data-theme') || 'light',
    openModal,
    closeModal,
    closeTopModal,
    showToast,
    setButtonLoading,
    serializeForm,
    setFormErrors,
    clearFormErrors,
    debounce,
    throttle,
    animate,
    fadeIn,
    fadeOut,
    slideIn
  };

  // Auto-init theme
  initTheme();
})();
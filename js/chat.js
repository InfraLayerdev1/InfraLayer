/**
 * Company AI — Chat Module
 * Handles chat sessions, messages, streaming, and RAG document ingestion
 */

(function () {
  'use strict';

  // ============================================================================
  // Configuration & State
  // ============================================================================

  const API_BASE = '';
  let currentSessionId = null;
  let isStreaming = false;
  let abortController = null;

  // ============================================================================
  // DOM References
  // ============================================================================

  const messagesContainer = document.getElementById('messages-container');
  const chatForm = document.getElementById('chat-form');
  const chatInput = document.getElementById('chat-input');
  const sendBtn = chatForm?.querySelector('.send-btn');
  const sessionsList = document.getElementById('sessions-list');
  const newChatBtn = document.getElementById('new-chat-btn');
  const searchInput = document.getElementById('search-input');

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
  // Session Management
  // ============================================================================

  async function loadSessions(query = '') {
    try {
      const endpoint = query ? `/sessions?search=${encodeURIComponent(query)}` : '/sessions';
      const sessions = await apiRequest(endpoint);
      renderSessions(sessions);
    } catch (err) {
      console.error('Failed to load sessions:', err);
      if (err.status === 401) {
        Auth.logout();
      }
    }
  }

  async function createSession(title = 'New Chat') {
    try {
      const session = await apiRequest('/sessions', {
        method: 'POST',
        body: JSON.stringify({ title })
      });
      await loadSessions();
      return session;
    } catch (err) {
      console.error('Failed to create session:', err);
      UI.showToast('Failed to create new chat', 'error');
      return null;
    }
  }

  async function deleteSession(sessionId) {
    try {
      await apiRequest(`/sessions/${sessionId}`, { method: 'DELETE' });
      if (currentSessionId === sessionId) {
        currentSessionId = null;
        messagesContainer.innerHTML = '';
      }
      await loadSessions();
    } catch (err) {
      console.error('Failed to delete session:', err);
      UI.showToast('Failed to delete session', 'error');
    }
  }

  function renderSessions(sessions) {
    if (!sessionsList) return;

    if (!sessions.length) {
      sessionsList.innerHTML = `
        <div class="sessions-empty">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
            <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
          </svg>
          <p>No conversations yet</p>
          <span class="hint">Click "New Chat" to start</span>
        </div>
      `;
      return;
    }

    sessionsList.innerHTML = sessions.map(session => `
      <article class="session-item ${session.id === currentSessionId ? 'active' : ''}"
               data-session-id="${session.id}"
               role="listitem"
               tabindex="0">
        <button class="session-title" aria-label="Open: ${escapeHtml(session.title)}">
          ${escapeHtml(session.title || 'Untitled')}
        </button>
        <button class="session-delete" aria-label="Delete: ${escapeHtml(session.title)}"
                data-action="delete" title="Delete">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
        </button>
      </article>
    `).join('');

    // Add click handlers
    sessionsList.querySelectorAll('.session-item').forEach(item => {
      item.addEventListener('click', e => {
        if (e.target.closest('.session-delete')) return;
        const sessionId = item.dataset.sessionId;
        loadMessages(sessionId);
      });
      item.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          item.click();
        }
      });
    });

    sessionsList.querySelectorAll('.session-delete').forEach(btn => {
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const sessionId = btn.closest('.session-item').dataset.sessionId;
        if (confirm('Delete this conversation?')) {
          deleteSession(sessionId);
        }
      });
    });
  }

  // ============================================================================
  // Message Rendering
  // ============================================================================

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function formatTime(date) {
    return new Date(date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function renderMessage(message, isStreaming = false) {
    const isUser = message.role === 'user';
    const messageId = message.id || `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;

    const messageEl = document.createElement('div');
    messageEl.className = `message ${isUser ? 'user' : 'assistant'} ${isStreaming ? 'streaming' : ''}`;
    messageEl.dataset.messageId = messageId;
    messageEl.setAttribute('role', isUser ? 'log' : 'article');
    messageEl.setAttribute('aria-label', `${isUser ? 'You' : 'Assistant'}: ${message.content?.slice(0, 100) || ''}`);

    const avatarSvg = isUser
      ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>';

    const time = message.created_at ? formatTime(message.created_at) : '';

    messageEl.innerHTML = `
      <div class="message-avatar" aria-hidden="true">${avatarSvg}</div>
      <div class="message-content">
        <div class="message-header">
          <span class="message-role">${isUser ? 'You' : 'Company AI'}</span>
          ${time ? `<time class="message-time">${time}</time>` : ''}
        </div>
        <div class="message-text ${isStreaming ? 'streaming-text' : ''}">${isStreaming ? '' : escapeHtml(message.content || '')}</div>
        ${isStreaming ? '<span class="streaming-cursor" aria-hidden="true"></span>' : ''}
        ${message.sources && message.sources.length ? `
          <details class="message-sources">
            <summary>Sources (${message.sources.length})</summary>
            <ul>${message.sources.map(s => `<li>${escapeHtml(s.title || s.filename || 'Document')}</li>`).join('')}</ul>
          </details>
        ` : ''}
      </div>
    `;

    return messageEl;
  }

  function appendMessage(message, isStreaming = false) {
    const el = renderMessage(message, isStreaming);
    messagesContainer.appendChild(el);
    scrollToBottom();
    return el;
  }

  function updateStreamingMessage(el, content) {
    const textEl = el.querySelector('.message-text');
    if (textEl) {
      textEl.textContent = content;
    }
    scrollToBottom();
  }

  function finalizeStreamingMessage(el, message) {
    el.classList.remove('streaming');
    const textEl = el.querySelector('.message-text');
    if (textEl) {
      textEl.classList.remove('streaming-text');
      textEl.textContent = message.content || '';
    }
    const cursor = el.querySelector('.streaming-cursor');
    cursor?.remove();

    if (message.sources && message.sources.length) {
      const sourcesEl = document.createElement('details');
      sourcesEl.className = 'message-sources';
      sourcesEl.innerHTML = `
        <summary>Sources (${message.sources.length})</summary>
        <ul>${message.sources.map(s => `<li>${escapeHtml(s.title || s.filename || 'Document')}</li>`).join('')}</ul>
      `;
      el.querySelector('.message-content').appendChild(sourcesEl);
    }
  }

  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function showWelcomeState() {
    messagesContainer.innerHTML = `
      <div class="welcome-state">
        <div class="welcome-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
          </svg>
        </div>
        <h2>Welcome to Company AI</h2>
        <p>Your intelligent knowledge assistant. Ask questions, get instant answers from your company's knowledge base.</p>
        <div class="welcome-suggestions">
          <button type="button" class="suggestion-chip" data-prompt="What is our company's remote work policy?">Remote work policy</button>
          <button type="button" class="suggestion-chip" data-prompt="How do I submit an expense report?">Expense reports</button>
          <button type="button" class="suggestion-chip" data-prompt="What are the engineering coding standards?">Coding standards</button>
          <button type="button" class="suggestion-chip" data-prompt="Summarize the latest all-hands meeting">All-hands summary</button>
        </div>
      </div>
    `;

    messagesContainer.querySelectorAll('.suggestion-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        chatInput.value = chip.dataset.prompt;
        chatInput.focus();
        handleSend(new Event('submit'));
      });
    });
  }

  // ============================================================================
  // Message Loading
  // ============================================================================

  async function loadMessages(sessionId) {
    currentSessionId = sessionId;
    messagesContainer.innerHTML = '<div class="loading-state"><div class="spinner"></div><p>Loading messages...</p></div>';

    // Update active session in sidebar
    sessionsList?.querySelectorAll('.session-item').forEach(item => {
      item.classList.toggle('active', item.dataset.sessionId === sessionId);
    });

    try {
      const messages = await apiRequest(`/sessions/${sessionId}/messages`);

      if (!messages.length) {
        showWelcomeState();
        return;
      }

      messagesContainer.innerHTML = '';
      messages.forEach(msg => appendMessage(msg));
    } catch (err) {
      console.error('Failed to load messages:', err);
      if (err.status === 401) {
        Auth.logout();
      } else {
        messagesContainer.innerHTML = `
          <div class="error-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            <p>Failed to load messages</p>
            <button class="btn btn-secondary" onclick="Chat.loadMessages('${sessionId}')">Retry</button>
          </div>
        `;
      }
    }
  }

  // ============================================================================
  // Chat (Non-streaming)
  // ============================================================================

  async function sendMessage(content) {
    if (!currentSessionId) {
      const session = await createSession(content.slice(0, 50));
      if (!session) return;
      currentSessionId = session.id;
    }

    if (isStreaming) return;

    // Add user message
    appendMessage({ role: 'user', content, created_at: new Date().toISOString() });
    chatInput.value = '';
    chatInput.disabled = true;
    sendBtn.disabled = true;
    isStreaming = true;

    // Create assistant message placeholder with loading state
    const assistantEl = appendMessage({ role: 'assistant', content: 'Thinking...' }, false);
    assistantEl.classList.add('loading');

    try {
      const res = await fetch(`${API_BASE}/ask`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${Auth.getToken()}`
        },
        body: JSON.stringify({
          session_id: currentSessionId,
          question: content,
          user_id: Auth.getUser()?.id
        })
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      // Replace loading message with actual response
      const finalMessage = {
        role: 'assistant',
        content: data.text || 'No response received',
        sources: data.sources || [],
        created_at: new Date().toISOString()
      };
      assistantEl.remove();
      appendMessage(finalMessage);

    } catch (err) {
      console.error('Chat error:', err);
      assistantEl.remove();
      appendMessage({
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
        created_at: new Date().toISOString()
      });
      UI.showToast('Failed to send message', 'error');
    } finally {
      isStreaming = false;
      chatInput.disabled = false;
      sendBtn.disabled = false;
      chatInput.focus();
    }
  }

  function stopStreaming() {
    // Not used in non-streaming mode
    isStreaming = false;
    chatInput.disabled = false;
    sendBtn.disabled = false;
    chatInput.focus();
  }

  // ============================================================================
  // Event Handlers
  // ============================================================================

  function handleSend(e) {
    e.preventDefault();
    const content = chatInput.value.trim();
    if (!content || isStreaming) return;
    sendMessage(content);
  }

  function handleNewChat() {
    currentSessionId = null;
    messagesContainer.innerHTML = '';
    showWelcomeState();
    chatInput.focus();
    sessionsList?.querySelectorAll('.session-item').forEach(item => {
      item.classList.remove('active');
    });
  }

  function handleSearch(e) {
    const query = e.target.value.trim();
    UI.debounce(() => loadSessions(query), 300)();
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  function init() {
    if (!Auth.isAuthenticated()) {
      showWelcomeState();
      return;
    }

    // Bind events
    chatForm?.addEventListener('submit', handleSend);
    newChatBtn?.addEventListener('click', handleNewChat);
    searchInput?.addEventListener('input', handleSearch);

    // Load sessions
    loadSessions();
    showWelcomeState();
  }

  // ============================================================================
  // Public API
  // ============================================================================

  window.Chat = {
    init,
    loadSessions,
    loadMessages,
    createSession,
    deleteSession,
    sendMessage,
    stopStreaming,
    getCurrentSessionId: () => currentSessionId,
    apiRequest
  };

  // Auto-init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
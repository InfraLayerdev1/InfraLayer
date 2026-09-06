"use client";

import { useState } from 'react';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  blocked?: boolean;
}

export default function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input;
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setInput('');
    setLoading(true);

    try {
      const response = await fetch('/api/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question: userMessage,
          userId: 'user-123',
          tenantId: 'tenant-456',
          role: 'employee',
          permissions: ['read:documents'],
        }),
      });

      const data = await response.json();
      
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.answer,
        blocked: data.blocked,
      }]);
    } catch (error) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Error: Failed to get response',
        blocked: true,
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">InfraLayer RAG Chat</h1>
      
      <div className="border rounded-lg p-4 mb-4 h-96 overflow-y-auto space-y-3">
        {messages.map((msg, i) => (
          <div key={i} className={`p-3 rounded ${msg.role === 'user' ? 'bg-blue-100 text-right' : msg.blocked ? 'bg-red-100' : 'bg-gray-100'}`}>
            <strong>{msg.role === 'user' ? 'You' : 'Assistant'}:</strong>
            <p>{msg.content}</p>
            {msg.blocked && <span className="text-red-600 text-sm">🛡️ Blocked by security policy</span>}
          </div>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask a question..."
          className="flex-1 p-2 border rounded"
          disabled={loading}
        />
        <button type="submit" disabled={loading || !input.trim()} className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50">
          {loading ? 'Sending...' : 'Send'}
        </button>
      </form>
    </div>
  );
}

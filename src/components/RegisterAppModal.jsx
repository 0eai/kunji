import React, { useState } from 'react';
import { X } from 'lucide-react';
import { registerApp } from '../services/identity';
import { useToast } from '../contexts/ToastContext';

const RegisterAppModal = ({ user, cryptoKey, onClose, onRegistered }) => {
  const { showToast } = useToast();
  const [form, setForm] = useState({ name: '', domain: '', iconUrl: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name.trim() || !form.domain.trim()) { setError('App name and domain are required.'); return; }
    setError('');
    setLoading(true);
    try {
      const result = await registerApp(user.uid, cryptoKey, {
        name: form.name.trim(),
        domain: form.domain.trim(),
        iconUrl: form.iconUrl.trim(),
      });
      onRegistered({ id: result.registeredAppId, name: form.name.trim(), domain: form.domain.trim(), publicKey: result.publicKey });
    } catch {
      setError('Failed to register app. Try again.');
      showToast('Registration failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-3xl w-full max-w-sm p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-white">Register App</h2>
          <button onClick={onClose} className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-[#27272a] transition-colors">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">App Name</label>
            <input
              type="text" autoFocus required
              value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              placeholder="My Web App"
              className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-600 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Domain</label>
            <input
              type="text" required
              value={form.domain} onChange={e => setForm(p => ({ ...p, domain: e.target.value }))}
              placeholder="app.example.com"
              className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-600 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-400 mb-1">Icon URL <span className="text-gray-600">(optional)</span></label>
            <input
              type="url"
              value={form.iconUrl} onChange={e => setForm(p => ({ ...p, iconUrl: e.target.value }))}
              placeholder="https://example.com/icon.png"
              className="w-full p-3 rounded-xl bg-black border border-[#27272a] text-white placeholder-gray-600 focus:ring-2 focus:ring-amber-500 focus:border-transparent outline-none"
            />
          </div>
          {error && <p className="text-red-400 text-sm">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} disabled={loading}
              className="flex-1 py-3 rounded-xl bg-[#27272a] hover:bg-[#3f3f46] text-white font-medium transition-colors">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex-1 py-3 rounded-xl bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-black font-semibold transition-colors">
              {loading ? 'Registering…' : 'Register'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default RegisterAppModal;

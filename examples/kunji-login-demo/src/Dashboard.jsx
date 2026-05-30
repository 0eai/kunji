import React from 'react';

export default function Dashboard({ sub, onLogout }) {
  return (
    <div className="bg-white border border-[#e6e8eb] rounded-3xl p-8 max-w-md w-full">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-11 h-11 bg-green-100 rounded-full flex items-center justify-center">
          <svg className="w-6 h-6 text-green-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4L19 7"/></svg>
        </div>
        <div>
          <h1 className="text-xl font-bold">Signed in</h1>
          <p className="text-gray-500 text-sm">Verified with kunji — no password</p>
        </div>
      </div>

      <p className="text-xs font-medium text-gray-500 mb-1">Your ID for this app (sub)</p>
      <code className="block w-full p-3 text-xs font-mono bg-[#f6f7f9] border border-[#e6e8eb] rounded-xl text-amber-700 break-all mb-2">
        {sub}
      </code>
      <p className="text-[11px] text-gray-400 leading-relaxed mb-6">
        This is the stable identifier this app received for you. It's the SHA-256 of your per-app public key —
        unique to this app, so other apps see a different ID.
      </p>

      <button onClick={onLogout}
        className="w-full py-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-black font-semibold transition-colors">
        Sign out
      </button>
    </div>
  );
}

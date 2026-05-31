import React from 'react';

// Catches render-time throws so a malformed doc / unexpected error shows a recoverable
// fallback instead of a blank white screen — important for a wallet on a sign-in attempt.
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    console.error('App error boundary caught:', error, info);
  }

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="h-[100dvh] w-full flex flex-col items-center justify-center gap-4 bg-paper text-ink px-6 text-center">
        <p className="text-[15px] font-medium">Something went wrong</p>
        <p className="text-[14px] text-muted max-w-xs leading-relaxed">
          kunji hit an unexpected error. Your vault is safe — reloading usually fixes it.
        </p>
        <button
          onClick={() => window.location.reload()}
          className="inline-flex items-center justify-center px-5 py-3 text-sm bg-accent-fill hover:bg-accent text-on-accent font-semibold rounded-full transition-colors"
        >
          Reload
        </button>
      </div>
    );
  }
}

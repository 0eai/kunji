// src/contexts/ToastContext.jsx
// Global toast notification system. Provides showToast(message, type) to any component.
// Types: 'success' (default), 'error', 'warning', 'info'
import { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext(null);

export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);

    const showToast = useCallback((message, type = 'success') => {
        const id = Date.now() + Math.random();
        setToasts(prev => [...prev, { id, message, type }]);
        setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3000);
    }, []);

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            <div className="fixed top-[max(1rem,env(safe-area-inset-top))] left-1/2 -translate-x-1/2 z-[300] flex flex-col gap-2 pointer-events-none" style={{ width: 'max-content', maxWidth: '90vw' }}>
                {toasts.map(t => (
                    <div
                        key={t.id}
                        className={`px-4 py-2 rounded-full shadow-lg text-[13px] font-medium text-center animate-fade
                            ${t.type === 'error' ? 'bg-danger text-white' :
                              t.type === 'warning' ? 'bg-accent text-white' :
                              'bg-ink text-paper'}`}
                    >
                        {t.message}
                    </div>
                ))}
            </div>
        </ToastContext.Provider>
    );
};

export const useToast = () => useContext(ToastContext);

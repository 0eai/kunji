// In-memory, per-session holder for the caller's public IP, echoed by the vaultWrite function
// (which sees it inherently as the TCP peer). The activity log encrypts it into each entry; it is
// never persisted in plaintext anywhere. Cleared on reload. Primed by any vault write — ordinary
// app writes (sign-in/register) populate it for later activity entries.
let sessionIp = null;

export const setSessionIp = (ip) => {
  if (typeof ip === 'string' && ip) sessionIp = ip;
};

export const getSessionIp = () => sessionIp;

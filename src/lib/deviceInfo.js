// Coarse, fingerprint-resistant device label for the activity log — browser family + OS only,
// no versions and never the full user-agent. It's only ever stored encrypted in the user's own
// log (and never sent to relying parties); this is just a "was this me?" affordance.
//
// Kept pure (parseDeviceLabel takes its inputs) so it's unit-testable without a browser.

const detectBrowser = (ua, uaData) => {
  if (uaData?.brands?.length) {
    const names = uaData.brands.map((b) => b.brand);
    if (names.some((n) => /Edge/i.test(n))) return 'Edge';
    if (names.some((n) => /Opera|OPR/i.test(n))) return 'Opera';
    if (names.some((n) => /Chrome|Chromium/i.test(n))) return 'Chrome';
  }
  if (/\bEdg\//.test(ua)) return 'Edge'; // Edge UA also contains "Chrome" — check first
  if (/\bOPR\/|\bOpera/.test(ua)) return 'Opera';
  if (/\bFirefox\/|\bFxiOS\//.test(ua)) return 'Firefox';
  if (/\bCriOS\//.test(ua)) return 'Chrome'; // Chrome on iOS
  if (/\bChrome\//.test(ua)) return 'Chrome';
  if (/\bSafari\//.test(ua) && /\bVersion\//.test(ua)) return 'Safari';
  return '';
};

const detectOS = (ua, uaData) => {
  const p = uaData?.platform;
  if (p) {
    if (/Android/i.test(p)) return 'Android';
    if (/iOS|iPhone|iPad/i.test(p)) return 'iOS';
    if (/Windows/i.test(p)) return 'Windows';
    if (/Chrome ?OS|CrOS/i.test(p)) return 'ChromeOS';
    if (/mac/i.test(p)) return 'macOS';
    if (/Linux/i.test(p)) return 'Linux';
  }
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows/.test(ua)) return 'Windows';
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Macintosh|Mac OS X/.test(ua)) return 'macOS';
  if (/Linux/.test(ua)) return 'Linux';
  return '';
};

/** Pure: derive a coarse "Browser · OS" label from a UA string (+ optional navigator.userAgentData). */
export const parseDeviceLabel = (ua = '', uaData = null) => {
  const browser = detectBrowser(ua, uaData);
  const os = detectOS(ua, uaData);
  if (browser && os) return `${browser} · ${os}`;
  return browser || os || '';
};

/** Current device's coarse label, read from navigator. Empty string when unavailable. */
export const deviceLabel = () => {
  if (typeof navigator === 'undefined') return '';
  return parseDeviceLabel(navigator.userAgent || '', navigator.userAgentData || null);
};

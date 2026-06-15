// issuer.kunji.cc — Verify-your-age (IDV) → OpenID4VCI offer. External (the CSP blocks inline scripts).
//   1. "Verify my age" → POST /idv/start → stash the opaque sid → redirect to the vendor's hosted
//      document + liveness flow (no third-party script on this page; CSP stays tight).
//   2. On return (a stashed sid), poll /idv/status?sid until verified → GET /credential-offer?sid → render
//      the app.kunji.cc/?offer= deep link. kunji only ever learns the verified result; the vendor holds the ID.
const WALLET = 'https://app.kunji.cc';
const SID_KEY = 'kunji_idv_sid';
const verifyBtn = document.getElementById('verify');
const statusEl = document.getElementById('status');
const offerCard = document.getElementById('offer');
const openLink = document.getElementById('open');

const reset = (msg) => {
  statusEl.textContent = msg || '';
  verifyBtn.disabled = false;
  verifyBtn.textContent = 'Verify my age';
};

verifyBtn.addEventListener('click', async () => {
  statusEl.textContent = '';
  verifyBtn.disabled = true;
  verifyBtn.textContent = 'Starting…';
  try {
    const r = await fetch('/idv/start', { method: 'POST' });
    if (r.status === 503) return reset('Age verification is being set up — check back soon.');
    if (!r.ok) throw new Error('start');
    const { sid, url } = await r.json();
    sessionStorage.setItem(SID_KEY, sid);
    window.location.assign(url); // redirect to the vendor's hosted document + liveness flow
  } catch {
    reset('Could not start verification. Please try again.');
  }
});

const showOffer = async (sid) => {
  statusEl.textContent = '';
  try {
    const r = await fetch(`/credential-offer?sid=${encodeURIComponent(sid)}`);
    if (!r.ok) throw new Error('offer');
    const { offerUri } = await r.json();
    sessionStorage.removeItem(SID_KEY); // the verified session is single-use (consumed server-side)
    openLink.href = `${WALLET}/?offer=${encodeURIComponent(offerUri)}`;
    verifyBtn.closest('.card').style.display = 'none'; // hide step 1
    offerCard.hidden = false;
  } catch {
    reset('Verified, but the credential offer failed. Please try again.');
  }
};

// Resume after returning from the vendor (a stashed sid means we were mid-verification).
const resume = () => {
  const sid = sessionStorage.getItem(SID_KEY);
  if (!sid) return;
  verifyBtn.disabled = true;
  verifyBtn.textContent = 'Checking…';
  statusEl.textContent = 'Confirming your verification…';
  const poll = async (tries) => {
    try {
      const r = await fetch(`/idv/status?sid=${encodeURIComponent(sid)}`);
      if (r.ok) {
        const { status } = await r.json();
        if (status === 'verified') return showOffer(sid);
        if (status === 'failed') {
          sessionStorage.removeItem(SID_KEY);
          return reset('Verification didn’t complete. You can try again.');
        }
      } else if (r.status === 404) {
        sessionStorage.removeItem(SID_KEY);
        return reset('That verification expired. Please start again.');
      }
    } catch {
      /* transient — keep polling */
    }
    if (tries <= 0) return reset('Still confirming… refresh in a moment.');
    setTimeout(() => poll(tries - 1), 2000);
  };
  poll(60); // ~2 minutes
};

resume();

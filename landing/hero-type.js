// Hero typewriter — cycles the last word of "No ___." through kunji's benefits-by-negation.
// Progressive enhancement only: the HTML already renders a static "Google." (the #type span +
// an sr-only copy), so with JS off, under prefers-reduced-motion, or for screen readers the hero
// reads "No Google." with no motion. Pure DOM text writes — the word list is static, no innerHTML.
(() => {
  const el = document.getElementById('type');
  if (!el) return;
  // Respect reduced motion: leave the static "Google." exactly as the HTML shipped it.
  if (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // Each completes "No ___." — a distinct kunji benefit: no gatekeeper, passwordless, privacy,
  // anonymity (no PII), no backend in the login path. "Google." is first to match the static fallback.
  const words = ['Google.', 'passwords.', 'trackers.', 'email.', 'middleman.'];
  const TYPE = 75; // ms per typed char
  const DELETE = 45; // ms per deleted char
  const HOLD = 1600; // ms a full word stays before deleting
  const GAP = 350; // ms blank before the next word types

  el.classList.add('typing'); // turns on the CSS caret (only present while animating)

  let w = 0; // current word index
  let i = words[0].length; // chars shown — start full, on the already-rendered "Google."
  let deleting = true; // begin by holding, then deleting (no initial re-type flash)

  const step = () => {
    const word = words[w];
    if (deleting) {
      i--;
      el.textContent = word.slice(0, i);
      if (i === 0) {
        deleting = false;
        w = (w + 1) % words.length;
        return setTimeout(step, GAP);
      }
      return setTimeout(step, DELETE);
    }
    i++;
    el.textContent = words[w].slice(0, i);
    if (i === words[w].length) {
      deleting = true;
      return setTimeout(step, HOLD);
    }
    return setTimeout(step, TYPE);
  };

  setTimeout(step, HOLD); // hold "Google." first, then start cycling
})();

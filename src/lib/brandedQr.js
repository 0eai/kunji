// Brand-styled QR rendering (qr-code-styling): extra-rounded modules + an embedded amber
// app-icon logo with a cleared quiet area (hideBackgroundDots), so the logo never overlaps
// data. Pure presentation — `data` is the QR payload unchanged. Shared by the wallet's QR
// surfaces; the widget and the demo carry their own copy (separate bundles).
import QRCodeStyling from 'qr-code-styling';

// The kunji app icon (amber tile + dark key) — same mark as public/icons/icon.svg, inlined
// as a data URI so it needs no network and works on any origin.
const APP_ICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">' +
      '<rect width="512" height="512" rx="116" fill="#f59e0b"/>' +
      '<g transform="rotate(-40 256 256)" fill="none" stroke="#1c1606" stroke-width="58" stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="240" cy="172" r="56" fill="#1c1606"/>' +
      '<path d="M240 172 V398"/><path d="M240 334 L300 314"/><path d="M240 334 L300 358"/>' +
      '</g></svg>',
  );

const INK = '#1a1a18';

/**
 * The canonical branded QR — the single source of truth for the look shared (byte-equal params,
 * since separate bundles can't import this) by the demo LoginPage and the rp.js widget.
 * Render into `el` (replacing its contents). `withLogo` overlays the amber app icon (default);
 * set false for long opaque payloads (the capability JWT).
 *
 * The logo is an OVERLAY <img> (img-src), NOT qr-code-styling's `image` — `image` fetches the
 * data-URI (connect-src) and a strict RP CSP blanks the whole QR. EC defaults to 'H' so the
 * opaque overlay's occluded center stays recoverable; `margin:0` keeps a single tight quiet zone
 * (the container's padding is the quiet zone).
 */
export const renderBrandedQr = (el, { data, size = 224, withLogo = true, ec = 'H', margin = 0 }) => {
  if (!el || !data) return;
  const qr = new QRCodeStyling({
    type: 'svg',
    width: size,
    height: size,
    data,
    margin,
    qrOptions: { errorCorrectionLevel: ec },
    backgroundOptions: { color: '#ffffff' },
    dotsOptions: { type: 'extra-rounded', color: INK },
    cornersSquareOptions: { type: 'extra-rounded', color: INK },
    cornersDotOptions: { color: INK },
  });
  el.replaceChildren();
  qr.append(el);
  if (withLogo) {
    el.style.position = 'relative';
    const logo = document.createElement('img');
    logo.src = APP_ICON;
    logo.alt = '';
    // A white plate (bg + padding) behind the amber tile = a cleared "quiet zone", so the logo
    // reads as punched-out, not overlapping the modules. Done in the DOM (no qr-code-styling
    // `image` fetch), so it stays CSP-robust; EC 'H' covers the ~7% it occludes.
    const px = Math.round(size * 0.26);
    logo.style.cssText = `position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${px}px;height:${px}px;padding:6px;background:#fff;border-radius:13px;box-sizing:border-box`;
    el.appendChild(logo);
  }
  return qr;
};

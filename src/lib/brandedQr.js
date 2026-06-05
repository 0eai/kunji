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
 * Render a brand-styled QR into `el` (replacing its contents). `withLogo` embeds the amber
 * app icon (default); set false for long opaque payloads. EC defaults to 'Q' (the lean v2
 * payload keeps density low even with the cleared logo area).
 */
export const renderBrandedQr = (el, { data, size = 256, withLogo = true, ec = 'Q' }) => {
  if (!el || !data) return;
  const qr = new QRCodeStyling({
    type: 'svg',
    width: size,
    height: size,
    data,
    margin: 8,
    qrOptions: { errorCorrectionLevel: ec },
    backgroundOptions: { color: '#ffffff' },
    dotsOptions: { type: 'extra-rounded', color: INK },
    cornersSquareOptions: { type: 'extra-rounded', color: INK },
    cornersDotOptions: { color: INK },
    ...(withLogo
      ? { image: APP_ICON, imageOptions: { imageSize: 0.35, margin: 4, hideBackgroundDots: true } }
      : {}),
  });
  el.replaceChildren();
  qr.append(el);
  return qr;
};

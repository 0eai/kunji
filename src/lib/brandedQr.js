// Brand-styled QR rendering (qr-code-styling): extra-rounded modules + the amber app-icon
// overlaid on a white squircle that clears a quiet zone, so the logo never overlaps the data.
// Pure presentation — `data` is the QR payload unchanged. The single source of truth: the wallet
// surfaces AND the rp.js widget both render through this; the demo carries a byte-equal copy
// (separate bundle).
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
    // roundSize:false — qr-code-styling otherwise floors the dot size, so `count*dotSize < size`
    // and it centers the pattern, baking a white margin INSIDE the svg that varies with payload
    // length (the source of the "inconsistent / too much padding" across surfaces). Fractional dots
    // fill `size` edge-to-edge, so the only quiet zone is the container's uniform padding.
    dotsOptions: { type: 'extra-rounded', color: INK, roundSize: false },
    cornersSquareOptions: { type: 'extra-rounded', color: INK },
    cornersDotOptions: { color: INK },
  });
  el.replaceChildren();
  qr.append(el);
  // Pin the generated SVG to exactly `size` and display:block — qr-code-styling sets width/height
  // attributes, but forcing it here removes the inline-baseline gap and guarantees every surface
  // frames an identically-sized QR (the wallet/demo otherwise relied on intrinsic sizing).
  const svg = el.querySelector('svg');
  if (svg) svg.style.cssText = `display:block;width:${size}px;height:${size}px`;
  if (withLogo) {
    el.style.position = 'relative';
    const logo = document.createElement('img');
    logo.src = APP_ICON;
    logo.alt = '';
    // The amber tile sits on a generous white squircle = a cleared "quiet zone", so the logo reads
    // as punched-out, floating clear of the modules (a thin ring crowds the dots). The plate (icon
    // + halo) is ~31% of width / ~10% of area — within EC 'H'. Done in the DOM (no qr-code-styling
    // `image` fetch) so it stays CSP-robust. Sizes are fractions of `size` so it scales.
    const halo = Math.round(size * 0.05); // ~11px white border on each side
    const plate = Math.round(size * 0.21) + halo * 2; // amber tile ~47px + the halo
    const radius = Math.round(size * 0.085); // ~19px squircle, matching the brand tile
    logo.style.cssText = `position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${plate}px;height:${plate}px;padding:${halo}px;background:#fff;border-radius:${radius}px;box-sizing:border-box`;
    el.appendChild(logo);
  }
  return qr;
};

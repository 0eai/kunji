// Shared branded-QR helper for the demo SPA (mirror of the wallet's src/lib/brandedQr.js — separate
// bundle, so copy not import). Used by LoginPage + CredentialsDemo.
import QRCodeStyling from 'qr-code-styling';

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

const SIZE = 224;
// Overlay the amber logo as an <img> (img-src), not qr-code-styling's fetched `image` (connect-src,
// which a strict CSP would blank); EC 'H' covers the occluded center; margin:0 + the container's p-3 is
// the single quiet zone.
export const renderBrandedQr = (el, data) => {
  if (!el || !data) return;
  const qr = new QRCodeStyling({
    type: 'svg',
    width: SIZE,
    height: SIZE,
    data,
    margin: 0,
    qrOptions: { errorCorrectionLevel: 'H' },
    backgroundOptions: { color: '#ffffff' },
    dotsOptions: { type: 'extra-rounded', color: '#1a1a18', roundSize: false },
    cornersSquareOptions: { type: 'extra-rounded', color: '#1a1a18' },
    cornersDotOptions: { color: '#1a1a18' },
  });
  el.replaceChildren();
  qr.append(el);
  const svg = el.querySelector('svg');
  if (svg) svg.style.cssText = `display:block;width:${SIZE}px;height:${SIZE}px`;
  el.style.position = 'relative';
  const logo = document.createElement('img');
  logo.src = APP_ICON;
  logo.alt = '';
  const halo = Math.round(SIZE * 0.05);
  const plate = Math.round(SIZE * 0.21) + halo * 2;
  const radius = Math.round(SIZE * 0.085);
  logo.style.cssText = `position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:${plate}px;height:${plate}px;padding:${halo}px;background:#fff;border-radius:${radius}px;box-sizing:border-box`;
  el.appendChild(logo);
};

// base64url so a payload rides safely in a URL query param.
export const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

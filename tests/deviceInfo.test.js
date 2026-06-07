import { describe, it, expect } from 'vitest';
import { parseDeviceLabel } from '../src/lib/deviceInfo.js';

describe('parseDeviceLabel — coarse browser · OS, no versions', () => {
  it('Chrome on Windows', () => {
    const ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    expect(parseDeviceLabel(ua)).toBe('Chrome · Windows');
  });

  it('Safari on iPhone', () => {
    const ua =
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
    expect(parseDeviceLabel(ua)).toBe('Safari · iPhone');
  });

  it('Firefox on Linux', () => {
    const ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0';
    expect(parseDeviceLabel(ua)).toBe('Firefox · Linux');
  });

  it('Edge on Windows (not misread as Chrome)', () => {
    const ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0';
    expect(parseDeviceLabel(ua)).toBe('Edge · Windows');
  });

  it('prefers userAgentData when present', () => {
    const uaData = { platform: 'macOS', brands: [{ brand: 'Google Chrome', version: '124' }] };
    expect(parseDeviceLabel('', uaData)).toBe('Chrome · macOS');
  });

  it('falls back gracefully to empty string on an unrecognized UA', () => {
    expect(parseDeviceLabel('totally unknown')).toBe('');
  });
});

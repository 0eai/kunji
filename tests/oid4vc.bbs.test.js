import { describe, it, expect } from 'vitest';
import { buildBbsVpToken, verifyVpToken, buildDcqlQuery, dcqlToVcQuery, BBS_VC_FORMAT } from '../src/lib/oid4vc.js';
import { mintBbsCredential, bbsKeyGen } from '../src/lib/vcBbs.js';

// BBS (v3) presented over the SAME OpenID4VP envelope as SD-JWT: a `vc+bbs` DCQL request → an unlinkable
// proof (a `bbs~` tagged-string vp_token) → verifyVpToken dispatches by tag. The SD-JWT path is unchanged
// (covered in oid4vc.test.js). See docs/oid4vc.md + verified-credentials.md §7.

const ISS = 'https://issuer.example';
const VCT = 'age';
const CID = 'https://verifier.example';
const NONCE = 'n1';

const setup = async () => {
  const { secretKey, publicKey } = await bbsKeyGen();
  const credential = await mintBbsCredential(secretKey, publicKey, {
    iss: ISS,
    vct: VCT,
    claims: { age_over_18: true, age_over_21: true },
    ttlSeconds: 365 * 86400,
  });
  return { publicKey, credential, getIssuerBbsKey: async () => publicKey };
};

describe('BBS over OpenID4VP (vc+bbs)', () => {
  it('buildDcqlQuery carries the requested format; dcqlToVcQuery extracts it', () => {
    const q = buildDcqlQuery({ id: 'age_cred', vct: VCT, disclose: ['age_over_18'], format: BBS_VC_FORMAT });
    expect(q.credentials[0].format).toBe('vc+bbs');
    expect(dcqlToVcQuery(q).format).toBe('vc+bbs');
    // default stays SD-JWT (back-compat)
    expect(buildDcqlQuery({ vct: VCT, disclose: [] }).credentials[0].format).toBe('vc+sd-jwt');
  });

  it('a vc+bbs vp_token verifies through verifyVpToken (dispatch by `bbs~` tag)', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const dcqlQuery = buildDcqlQuery({ id: 'age_cred', vct: VCT, disclose: ['age_over_18'], format: BBS_VC_FORMAT });
    const token = await buildBbsVpToken({ credential, disclose: ['age_over_18'], clientId: CID, nonce: NONCE, issuerPublicKey: publicKey });
    expect(token.startsWith('bbs~')).toBe(true);
    const v = await verifyVpToken({ vpToken: { age_cred: token }, dcqlQuery, getIssuerBbsKey, clientId: CID, nonce: NONCE });
    expect(v.ok).toBe(true);
    expect(v.claims).toEqual({ age_over_18: true });
    expect(v.vct).toBe(VCT);
  });

  it('rejects a BBS proof when the request asked for SD-JWT (format enforcement) [S25]', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const token = await buildBbsVpToken({ credential, disclose: ['age_over_18'], clientId: CID, nonce: NONCE, issuerPublicKey: publicKey });
    const sdjwtRequest = buildDcqlQuery({ id: 'age_cred', vct: VCT, disclose: ['age_over_18'] }); // default vc+sd-jwt
    const v = await verifyVpToken({ vpToken: { age_cred: token }, dcqlQuery: sdjwtRequest, getIssuerBbsKey, getIssuerKeys: async () => [], clientId: CID, nonce: NONCE });
    expect(v.ok).toBe(false);
    expect(v.error).toBe('format_mismatch');
  });

  it('rejects a wrong nonce and an unmet predicate', async () => {
    const { publicKey, credential, getIssuerBbsKey } = await setup();
    const dcqlQuery = buildDcqlQuery({ id: 'age_cred', vct: VCT, disclose: ['age_over_18'], format: BBS_VC_FORMAT });
    const token = await buildBbsVpToken({ credential, disclose: ['age_over_18'], clientId: CID, nonce: NONCE, issuerPublicKey: publicKey });
    const wrongNonce = await verifyVpToken({ vpToken: { age_cred: token }, dcqlQuery, getIssuerBbsKey, clientId: CID, nonce: 'WRONG' });
    expect(wrongNonce.ok).toBe(false);
    // ask for a claim that wasn't disclosed → predicate_failed (the disclosed set is bound by the proof)
    const dq2 = buildDcqlQuery({ id: 'age_cred', vct: VCT, disclose: ['age_over_21'], format: BBS_VC_FORMAT });
    const pf = await verifyVpToken({ vpToken: { age_cred: token }, dcqlQuery: dq2, getIssuerBbsKey, clientId: CID, nonce: NONCE });
    expect(pf.ok).toBe(false);
    expect(pf.error).toBe('predicate_failed');
  });
});

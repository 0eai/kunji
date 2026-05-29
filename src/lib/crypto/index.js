// lib/crypto/index.js — Barrel re-export for backwards compatibility
//
// All existing `import { ... } from '../../lib/crypto'` statements
// continue to work unchanged. New code can import from specific
// sub-modules for clarity:
//
//   import { encryptData, decryptData } from '../../lib/crypto/aes';
//   import { generateRSAKeyPair }       from '../../lib/crypto/rsa';
//   import { deriveECDHSharedSecret }   from '../../lib/crypto/ecdh';

export {
    // AES-256-GCM
    generateSalt,
    getDefaultIterations,
    generateMasterKey,
    exportKey,
    importMasterKey,
    deriveKeyFromPasskey,
    deriveKeyArgon2id,
    encryptData,
    decryptData,
    keyToUrlString,
    keyFromUrlString,
} from './aes';

export {
    // RSA-4096-OAEP
    generateRSAKeyPair,
    exportRSAPublicKey,
    exportRSAPrivateKey,
    importRSAPublicKey,
    importRSAPrivateKey,
    encryptRSA,
    decryptRSA,
} from './rsa';

export {
    // ECDH P-256
    generateECDHKeyPair,
    exportECDHPublicKey,
    exportECDHPrivateKey,
    importECDHPublicKey,
    importECDHPrivateKey,
    deriveECDHSharedSecret,
} from './ecdh';

export {
    // Ed25519 — Connected Apps signing
    generateEd25519KeyPair,
    exportEd25519SecretKey,
    exportEd25519PublicKey,
    importEd25519SecretKey,
    importEd25519PublicKey,
    signWithEd25519,
    verifyEd25519Signature,
} from './ed25519';

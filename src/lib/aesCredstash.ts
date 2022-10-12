import { createCipheriv, createDecipheriv, createHmac } from 'crypto';
import { DEFAULT_DIGEST } from '../defaults';
import { KeyService } from './keyService';
import { SecretRecord } from '../types';

const LEGACY_NONCE = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

const getHmacKey = (
  key: Uint8Array,
  ciphertext: Uint8Array,
  digestMethod: string,
) => createHmac(digestMethod, key)
  .update(ciphertext)
  .digest()
  .toString('hex');

const halveKey = (key: Uint8Array) => {
  const half = Math.floor(key.length / 2);
  return {
    dataKey: key.slice(0, half),
    hmacKey: key.slice(half),
  };
};

const sealAesCtr = (
  plaintext: string,
  key: Uint8Array,
  nonce: Uint8Array,
  digest: string,
) => {
  const { dataKey, hmacKey } = halveKey(key);
  const bits = dataKey.length * 8;
  const encryptor = createCipheriv(`aes-${bits}-ctr`, dataKey, nonce);
  const ciphertext = Buffer.concat([encryptor.update(plaintext), encryptor.final()]);
  return {
    ciphertext,
    hmac: getHmacKey(hmacKey, ciphertext, digest),
  };
};

const openAesCtr = (
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  expectedHmac: string | Uint8Array,
  digestMethod: string,
  name: string,
) => {
  const { dataKey, hmacKey } = halveKey(key);
  const bits = dataKey.length * 8;
  const hmac = getHmacKey(hmacKey, ciphertext, digestMethod);

  // Unicreds is sending a byte array of the hex string, so we need to unwrap it
  let actualExpectedHmac = expectedHmac;
  if (expectedHmac instanceof Uint8Array) {
    actualExpectedHmac = String.fromCharCode(...expectedHmac)
  }

  if (hmac !== actualExpectedHmac) {
    throw new Error(`Computed HMAC on ${name} does not match stored HMAC`);
  }

  const decryptor = createDecipheriv(`aes-${bits}-ctr`, dataKey, nonce);
  const buffer = Buffer.concat([decryptor.update(ciphertext), decryptor.final()]);
  return buffer.toString('utf-8');
};

/**
 * Encrypts `secret` using the key service.
 * You can decrypt with the companion method `open_aes_ctr_legacy`.
 * generate a 64 byte key.
 * Half will be for data encryption, the other half for HMAC
 * @param keyService
 * @param secret
 * @param digest
 */
export const sealAesCtrLegacy = async (
  keyService: KeyService,
  secret: string,
  digest = DEFAULT_DIGEST,
) => {
  const { key, encodedKey } = await keyService.generateDataKey(64);
  const { ciphertext, hmac } = sealAesCtr(secret, key, LEGACY_NONCE, digest);

  return {
    key: Buffer.from(encodedKey).toString('base64'),
    contents: ciphertext.toString('base64'),
    hmac,
    digest,
  };
};

/**
 * Decrypts secrets stored by `seal_aes_ctr_legacy`.
 * Assumes that the plaintext is unicode (non-binary).
 */
export const openAesCtrLegacy = async (
  keyService: KeyService,
  record: SecretRecord,
) => {
  const key = await keyService.decrypt(record.key);
  const digestMethod = record.digest || DEFAULT_DIGEST;
  const ciphertext = Buffer.from(record.contents, 'base64');
  let hmac;
  if (typeof record.hmac === 'object' && 'value' in record.hmac) {
    hmac = record.hmac.value;
  } else {
    hmac = record.hmac;
  }
  return openAesCtr(key, LEGACY_NONCE, ciphertext, hmac, digestMethod, record.name);
};

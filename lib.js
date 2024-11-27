'use strict'

const crypto = require('node:crypto')
const { subtle } = require('node:crypto').webcrypto


/// ////////////////////////////////////////////////////////////////////////////////
// Cryptographic Primitives
//
// All of the cryptographic functions you need for this assignment
// are contained within this library.
//
// The parameter and return types are designed to be as convenient as possible.
// The only conversion you will need in messenger.js will be when converting
// the result of decryptWithGCM (an ArrayBuffer) to a string.
//
// Any argument to a lib.js function should either be a string or a value
// returned by a lib.js function.
/// ////////////////////////////////////////////////////////////////////////////////

const govEncryptionDataStr = 'AES-GENERATION'

function bufferToString (arr) {
  // Converts from ArrayBuffer to string
  // Used to go from output of decryptWithGCM to string
  return Buffer.from(arr).toString()
}

function genRandomSalt (len = 16) {
  return crypto.getRandomValues(new Uint8Array(len))
}

async function cryptoKeyToJSON (cryptoKey) {
  const keyJWK = await crypto.subtle.exportKey('jwk', cryptoKey)

  // Dynamically set key_ops based on key type and usage
  if (!keyJWK.key_ops || keyJWK.key_ops.length === 0) {
    keyJWK.key_ops = cryptoKey.usages.length > 0 ? cryptoKey.usages : ['deriveKey']
  }

  console.log('[cryptoKeyToJSON] Exported Public Key JSON:', keyJWK)
  return keyJWK
}

async function generateEG () {
  const keypair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-384' },
    true, // Extractable (can be exported)
    ['deriveKey'] // Key usage for private key
  )

  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }

  // Validate keys
  if (!(keypairObject.pub instanceof CryptoKey)) {
    console.error('[generateEG] Generated public key is not a valid CryptoKey:', keypairObject.pub)
    throw new Error('Generated public key is not a valid CryptoKey!')
  }

  if (!(keypairObject.sec instanceof CryptoKey)) {
    console.error('[generateEG] Generated private key is not a valid CryptoKey:', keypairObject.sec)
    throw new Error('Generated private key is not a valid CryptoKey!')
  }

  console.log('Generated Key Pair:', keypairObject)
  return keypairObject
}
async function computeDH (myPrivateKey, theirPublicKey) {
  if (!(myPrivateKey instanceof CryptoKey)) {
    throw new TypeError('[computeDH] Invalid private key: must be a CryptoKey.')
  }

  if (!(theirPublicKey instanceof CryptoKey)) {
    throw new TypeError('[computeDH] Invalid public key: must be a CryptoKey.')
  }

  console.log('[computeDH] Computing shared secret...')

  try {
    const derivedKey = await subtle.deriveKey(
      { name: 'ECDH', public: theirPublicKey },
      myPrivateKey,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign', 'verify']
    )

    console.log('[computeDH] Shared secret derived successfully.')
    return derivedKey
  } catch (err) {
    console.error('[computeDH] Failed to compute shared secret:', err.message)
    throw new Error(`computeDH failed: ${err.message}`)
  }
}

async function verifyWithECDSA (publicKey, message, signature) {
  // returns true if signature is correct for message and publicKey
  // publicKey should be pair.pub from generateECDSA
  // message must be a string
  // signature must be exact output of signWithECDSA
  // returns true if verification is successful and false is fails
  return await subtle.verify({ name: 'ECDSA', hash: { name: 'SHA-384' } }, publicKey, signature, Buffer.from(message))
}

async function HMACtoAESKey (key, data, exportToArrayBuffer = false) {
  // Performs HMAC to derive a new key with derivedKeyAlgorithm AES
  // if exportToArrayBuffer is true, return key as ArrayBuffer. Otherwise, output CryptoKey
  // key is a CryptoKey
  // data is a string

  // first compute HMAC output
  const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, Buffer.from(data))

  // Then, re-import with derivedKeyAlgorithm AES-GCM
  const out = await subtle.importKey('raw', hmacBuf, 'AES-GCM', true, ['encrypt', 'decrypt'])

  // If exportToArrayBuffer is true, exportKey as ArrayBuffer
  // (Think: what part of the assignment can this help with?)
  if (exportToArrayBuffer) {
    return await subtle.exportKey('raw', out)
  }

  // otherwise, export as cryptoKey
  return out
}

async function HMACtoHMACKey (key, data) {
  // Input validation
  if (!(key instanceof CryptoKey)) {
    throw new TypeError('Invalid key: key must be a valid CryptoKey.')
  }
  if (typeof data !== 'string' || data.trim() === '') {
    throw new TypeError('Invalid data: data must be a non-empty string.')
  }

  try {
    // Perform HMAC signing to derive an intermediate buffer
    const hmacBuf = await subtle.sign({ name: 'HMAC' }, key, Buffer.from(data))

    // Import the buffer as a new HMAC key
    const derivedKey = await subtle.importKey(
      'raw',
      hmacBuf,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign']
    )

    return derivedKey
  } catch (err) {
    // Ensure any cryptographic errors are wrapped with context
    throw new Error(`HMACtoHMACKey failed: ${err.message}`)
  }
}
async function HKDF (inputKey, salt, infoStr) {
  if (!(inputKey instanceof CryptoKey)) {
    throw new TypeError('[HKDF] Invalid inputKey: must be a CryptoKey.')
  }

  if (!(salt instanceof CryptoKey)) {
    throw new TypeError('[HKDF] Invalid salt: must be a CryptoKey.')
  }

  console.log('[HKDF] Starting HKDF...')

  const inputKeyRaw = await subtle.exportKey('raw', inputKey)
  const inputKeyHKDF = await subtle.importKey('raw', inputKeyRaw, 'HKDF', false, ['deriveKey'])

  console.log('[HKDF] inputKey successfully converted.')

  const hkdfOut1 = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: Buffer.from('salt1'),
      info: Buffer.from(infoStr)
    },
    inputKeyHKDF,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const hkdfOut2 = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: Buffer.from('salt2'),
      info: Buffer.from(infoStr)
    },
    inputKeyHKDF,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  console.log('[HKDF] HKDF outputs derived successfully.')
  return [hkdfOut1, hkdfOut2]
}
async function encryptWithGCM (key, plaintext, iv, authenticatedData = '') {
  if (!(key instanceof CryptoKey)) throw new Error('[encryptWithGCM] Invalid key: must be a CryptoKey.')
  if (!(iv instanceof Uint8Array)) throw new Error('[encryptWithGCM] Invalid IV: must be a Uint8Array.')

  const plaintextBuffer = Buffer.from(plaintext, 'utf-8')
  const additionalDataBuffer = Buffer.from(authenticatedData)

  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: additionalDataBuffer },
      key,
      plaintextBuffer
    )

    console.log('[encryptWithGCM] Encryption successful.')
    return ciphertext
  } catch (err) {
    console.error('[encryptWithGCM] Encryption failed:', err.message)
    throw new Error(`encryptWithGCM failed: ${err.message}`)
  }
}
async function decryptWithGCM (key, ciphertext, iv, authenticatedData = '') {
  if (!(key instanceof CryptoKey)) throw new TypeError('[decryptWithGCM] Invalid key: must be a CryptoKey.')
  if (!(iv instanceof Uint8Array)) throw new TypeError('[decryptWithGCM] Invalid IV: must be a Uint8Array.')

  // Convert ciphertext to ArrayBuffer if it's not already
  const ciphertextBuffer = ciphertext instanceof ArrayBuffer ? ciphertext : Buffer.from(ciphertext)

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: Buffer.from(authenticatedData) },
      key,
      ciphertextBuffer
    )

    console.log('[decryptWithGCM] Decryption successful.')
    return Buffer.from(plaintext).toString('utf-8') // Convert to string
  } catch (err) {
    console.error('[decryptWithGCM] Decryption failed:', err.message)
    throw new Error(`decryptWithGCM failed: ${err.message}`)
  }
}

/// /////////////////////////////////////////////////////////////////////////////
// Addtional ECDSA functions for test-messenger.js
//
// YOU DO NOT NEED THESE FUNCTIONS FOR MESSENGER.JS,
// but they may be helpful if you want to write additional
// tests for certificate signatures in test-messenger.js.
/// /////////////////////////////////////////////////////////////////////////////

async function generateECDSA () {
  // returns a pair of Digital Signature Algorithm keys as an object
  // private key is keypairObject.sec
  // public key is keypairObject.pub
  const keypair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify'])
  const keypairObject = { pub: keypair.publicKey, sec: keypair.privateKey }
  return keypairObject
}

async function signWithECDSA (privateKey, message) {
  // returns signature of message with privateKey
  // privateKey should be pair.sec from generateECDSA
  // message is a string
  // signature returned as an ArrayBuffer
  return await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, privateKey, Buffer.from(message))
}

module.exports = {
  govEncryptionDataStr,
  bufferToString,
  genRandomSalt,
  cryptoKeyToJSON,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  generateECDSA,
  signWithECDSA
}

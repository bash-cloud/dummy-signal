'use strict'

/** ******* Imports ********/
const {
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM, // async
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')
const { subtle, CryptoKey } = require('node:crypto').webcrypto
const crypto = require('node:crypto')


/** ******* Implementation ********/
class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // Session state for each user
    this.certs = {} // Certificates of other users
    this.EGKeyPair = {} // Keypair generated for your client

    console.log('MessengerClient initialized with Certificate Authority and Government public keys.')
  }

  async generateCertificate (username) {
    console.log('[generateCertificate] Generating certificate for user:', username)
    this.EGKeyPair = await generateEG()

    const publicKeyJSON = await cryptoKeyToJSON(this.EGKeyPair.pub)
    console.log('[generateCertificate] Exported Public Key JSON:', publicKeyJSON)

    return { username, publicKey: publicKeyJSON }
  }

  async receiveCertificate (certificate, signature) {
    console.log(`[receiveCertificate] Verifying certificate for user: ${certificate.username}`)
    const certString = JSON.stringify(certificate)

    try {
      const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
      if (!isValid) throw new Error('Certificate verification failed!')
      this.certs[certificate.username] = certificate
      console.log(`[receiveCertificate] Certificate for user ${certificate.username} stored successfully.`)
    } catch (err) {
      console.error('[receiveCertificate] Verification failed:', err.message)
      throw err
    }
  }

  async initializeSession (username, recipientPublicKey) {
    console.log(`[initializeSession] Initializing session with user: ${username}`)

    // Generate your DH key pair
    const DHKeyPair = await generateEG()

    // Compute shared secret using Diffie-Hellman
    const sharedSecret = await computeDH(DHKeyPair.sec, recipientPublicKey)

    // Generate initial keys using HKDF
    const saltRaw = Buffer.from('salt-init')
    const salt = await crypto.subtle.importKey(
      'raw',
      saltRaw,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )

    const [rootKey, sendingChainKey] = await HKDF(sharedSecret, salt, 'ratchet-init')

    this.conns[username] = {
      rootKey,
      sendingChainKey,
      receivingChainKey: rootKey, // Set the receiving chain key to the root key initially
      DHKeyPair,
      receivedDHKey: null, // Will store the last received DH public key
      sendCounter: 0,
      receiveCounter: 0
    }

    console.log(`[initializeSession] Session initialized for user: ${username}`)
  }

  async sendMessage (name, plaintext) {
    console.log(`[sendMessage] Sending message to: ${name}`)

    const recipientCert = this.certs[name]
    if (!recipientCert) throw new Error(`[sendMessage] No certificate found for user: ${name}`)

    let recipientPublicKey
    if (recipientCert.publicKey instanceof CryptoKey) {
      recipientPublicKey = recipientCert.publicKey
    } else {
      recipientPublicKey = await crypto.subtle.importKey(
        'jwk',
        recipientCert.publicKey,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      )
    }

    if (!this.conns[name]) {
      console.log(`[sendMessage] Initializing session with user: ${name}`)
      await this.initializeSession(name, recipientPublicKey)
    }

    const conn = this.conns[name]

    // Ensure sendingChainKey is valid
    if (!(conn.sendingChainKey instanceof CryptoKey)) {
      throw new Error('[sendMessage] Invalid sendingChainKey: must be a CryptoKey.')
    }

    // Perform symmetric ratchet to derive encryption key
    const { newChainKey, encryptionKey } = await this.performSymmetricRatchet(conn.sendingChainKey)
    conn.sendingChainKey = newChainKey
    // Add this to `sendMessage` and `receiveMessage` after performing the symmetric ratchet
    console.log('[Symmetric Ratchet] Encryption Key:', encryptionKey)
    console.log('[Symmetric Ratchet] Chain Key:', newChainKey)

    // Encrypt the plaintext
    const iv = genRandomSalt()
    const ciphertext = await encryptWithGCM(encryptionKey, plaintext, iv, '')
    console.log('[sendMessage] Message encrypted successfully.')

    // Include the current DH public key in the header
    const header = {
      iv,
      dhKey: await cryptoKeyToJSON(conn.DHKeyPair.pub)
    }

    return [header, ciphertext]
  }

  async receiveMessage (name, [header, ciphertext]) {
    console.log(`[receiveMessage] Receiving message from: ${name}`)

    let conn = this.conns[name]
    if (!conn) {
      console.log(`[receiveMessage] No session for user ${name}, initializing.`)
      const recipientCert = this.certs[name]
      const recipientPublicKey = await crypto.subtle.importKey(
        'jwk',
        recipientCert.publicKey,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      )
      await this.initializeSession(name, recipientPublicKey)
      conn = this.conns[name]
    }

    // Perform DH ratchet if a new DH key is received
    if (header.dhKey) {
      const receivedDHKey = await crypto.subtle.importKey(
        'jwk',
        header.dhKey,
        { name: 'ECDH', namedCurve: 'P-384' },
        true,
        []
      )
      await this.performDHRatchet(name, receivedDHKey)
    }

    // Ensure receivingChainKey is valid
    if (!(conn.receivingChainKey instanceof CryptoKey)) {
      throw new Error('[receiveMessage] Invalid receivingChainKey: must be a CryptoKey.')
    }

    // Perform symmetric ratchet for decryption
    const { newChainKey, encryptionKey } = await this.performSymmetricRatchet(conn.receivingChainKey)
    conn.receivingChainKey = newChainKey
    // Add this to `sendMessage` and `receiveMessage` after performing the symmetric ratchet
    console.log('[Symmetric Ratchet] Encryption Key:', encryptionKey)
    console.log('[Symmetric Ratchet] Chain Key:', newChainKey)

    // Decrypt the ciphertext
    const iv = new Uint8Array(header.iv)
    console.log('[receiveMessage] IV:', iv)

    // Ensure ciphertext is a valid ArrayBuffer
    const binaryCiphertext = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext)
    console.log('[receiveMessage] Ciphertext:', binaryCiphertext)

    try {
      const plaintext = await decryptWithGCM(encryptionKey, ciphertext, iv, '')
      console.log('[receiveMessage] Message decrypted successfully.')
      return plaintext
    } catch (err) {
      console.error('[receiveMessage] Failed to decrypt message:', err.message)
      throw new Error(`decryptWithGCM failed: ${err.message}`)
    }
  }

  async performSymmetricRatchet (chainKey) {
    // Ensure chainKey is valid
    if (!(chainKey instanceof CryptoKey)) {
      console.error('[performSymmetricRatchet] Invalid chainKey:', chainKey)
      throw new Error('[performSymmetricRatchet] Invalid chainKey: must be a CryptoKey.')
    }

    // Derive a new chain key and encryption key
    const newChainKey = await HMACtoHMACKey(chainKey, 'chain-key-derivation')
    const encryptionKey = await HMACtoAESKey(chainKey, 'encryption-key-derivation')

    console.log('[performSymmetricRatchet] Derived newChainKey:', newChainKey)
    console.log('[performSymmetricRatchet] Derived encryptionKey:', encryptionKey)

    return { newChainKey, encryptionKey }
  }

  async performDHRatchet (username, receivedDHKey) {
    console.log(`[performDHRatchet] Performing DH ratchet with user: ${username}`)
    const conn = this.conns[username]

    // Step 1: Compute shared secret using received DH key and current private key
    const sharedSecret = await computeDH(conn.DHKeyPair.sec, receivedDHKey)

    // Step 2: Derive new rootKey and receivingChainKey
    const [newRootKey, newReceivingChainKey] = await HKDF(sharedSecret, conn.rootKey, 'ratchet-step')
    console.log('[performDHRatchet] New Root Key:', newRootKey)
    console.log('[performDHRatchet] New Receiving Chain Key:', newReceivingChainKey)

    // Step 3: Rotate DH key pair
    const newDHKeyPair = await generateEG()

    // Step 4: Compute new shared secret for sending chain key
    const newSharedSecret = await computeDH(newDHKeyPair.sec, receivedDHKey)
    const [_, newSendingChainKey] = await HKDF(newSharedSecret, newRootKey, 'ratchet-step')
    console.log('[performDHRatchet] New Sending Chain Key:', newSendingChainKey)

    // Step 5: Update session state
    conn.rootKey = newRootKey
    conn.receivingChainKey = newReceivingChainKey
    conn.sendingChainKey = newSendingChainKey
    conn.DHKeyPair = newDHKeyPair
    conn.receivedDHKey = receivedDHKey

    console.log(`[performDHRatchet] DH ratchet completed for user: ${username}`)
  }
}

module.exports = { MessengerClient }

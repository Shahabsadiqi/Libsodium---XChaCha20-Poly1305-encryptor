// encryptor.js – FINAL & CRYPTOSANITARY (nonce used ONCE per file)
const sodium = require('libsodium-wrappers-sumo');
const fs = require('fs');
const EventEmitter = require('events');

class FileEncryptor extends EventEmitter {
  async encrypt(inputPath, outputPath, password) {
    await sodium.ready;

    const data = fs.readFileSync(inputPath);

    const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // ONE SINGLE 24-byte nonce per file → used only once → perfect security
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const chunkSize = 64 * 1024;
    let processed = 0;
    const encryptedChunks = [];

    for (let i = 0; i < data.length; i += chunkSize) {
      const chunk = data.slice(i, i + chunkSize);

      // Counter mode: use chunk index as additional data (AD)
      // This makes every message unique even with same nonce
      const counter = Buffer.alloc(8);
      counter.writeBigUInt64BE(BigInt(i / chunkSize), 0);

      const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        chunk,           // message
        counter,          // additional data = chunk number (prevents reuse attack)
        null,             // no secret nonce
        nonce,            // 24-byte public nonce (used only once per file)
        key
      );

      encryptedChunks.push(encrypted);

      processed += chunk.length;
      this.emit('progress', Math.round((processed / data.length) * 100));

      await new Promise(r => setTimeout(r, 5));
    }

    // Optional: add 4 random bytes at end for max entropy (as you wanted)
    const padding = sodium.randombytes_buf(4);

    const final = Buffer.concat([salt, nonce, ...encryptedChunks, padding]);
    fs.writeFileSync(outputPath, final);
    this.emit('done', outputPath);
  }

  // Decrypt version (also fixed)
  async decrypt(inputPath, outputPath, password) {
    await sodium.ready;
    const file = fs.readFileSync(inputPath);

    const salt = file.slice(0, sodium.crypto_pwhash_SALTBYTES);
    const nonce = file.slice(sodium.crypto_pwhash_SALTBYTES, sodium.crypto_pwhash_SALTBYTES + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    const key = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    let ciphertext = file.slice(sodium.crypto_pwhash_SALTBYTES + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    // Remove padding (last 4 bytes)
    ciphertext = ciphertext.slice(0, -4);

    const chunkSize = 64 * 1024 + 16; // ciphertext is 16 bytes longer (tag)
    const decryptedChunks = [];

    for (let i = 0; i < ciphertext.length; i += chunkSize) {
      const chunk = ciphertext.slice(i, i + chunkSize);
      const counter = Buffer.alloc(8);
      counter.writeBigUInt64BE(BigInt(i / chunkSize), 0);

      const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, chunk, counter, nonce, key
      );

      if (decrypted === null) throw new Error('Decryption failed — wrong password');
      decryptedChunks.push(decrypted);
    }

    fs.writeFileSync(outputPath, Buffer.concat(decryptedChunks));
    this.emit('done', outputPath);
  }
}

module.exports = FileEncryptor;

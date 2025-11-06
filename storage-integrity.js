// storage-integrity.js
// Provides HMAC-based integrity protection for Chrome storage

class StorageIntegrityManager {
  constructor() {
    this.secret = null;
    this.initialized = false;
  }

  async initialize() {
    if (this.initialized) return;

    // Generate or retrieve secret key
    const stored = await chrome.storage.local.get(['integritySecret']);
    if (stored.integritySecret) {
      this.secret = stored.integritySecret;
    } else {
      // Generate new secret on first run
      this.secret = this.generateSecret();
      await chrome.storage.local.set({ integritySecret: this.secret });
      console.log('🔐 Storage integrity secret generated');
    }
    this.initialized = true;
  }

  generateSecret() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async computeHMAC(data) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    const messageData = encoder.encode(JSON.stringify(data));

    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign', 'verify']
    );

    const signature = await crypto.subtle.sign('HMAC', key, messageData);
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async saveWithIntegrity(key, data) {
    await this.initialize();

    const hmac = await this.computeHMAC(data);
    const wrappedData = {
      data: data,
      hmac: hmac,
      version: '1.0',
      timestamp: Date.now()
    };

    await chrome.storage.local.set({ [key]: wrappedData });
    console.log(`✅ Saved ${key} with integrity protection`);
  }

  async loadWithIntegrity(key) {
    await this.initialize();

    const stored = await chrome.storage.local.get([key]);
    if (!stored[key]) {
      console.warn(`⚠️ No data found for key: ${key}`);
      return null;
    }

    const wrappedData = stored[key];

    // Verify structure
    if (!wrappedData.data || !wrappedData.hmac) {
      console.error(`❌ Storage data missing integrity fields for key: ${key}`);
      return null;
    }

    // Verify HMAC
    const computedHMAC = await this.computeHMAC(wrappedData.data);
    if (computedHMAC !== wrappedData.hmac) {
      console.error(`🚨 INTEGRITY VIOLATION: Storage data for ${key} has been tampered with!`);
      return null;
    }

    // Verify version
    if (wrappedData.version !== '1.0') {
      console.warn(`⚠️ Storage data version mismatch for ${key}: ${wrappedData.version}`);
    }

    console.log(`✅ Loaded ${key} - integrity verified`);
    return wrappedData.data;
  }

  // Utility: Check if data exists and is valid
  async isValid(key) {
    const data = await this.loadWithIntegrity(key);
    return data !== null;
  }

  // Utility: Delete data
  async deleteWithIntegrity(key) {
    await chrome.storage.local.remove([key]);
    console.log(`🗑️ Deleted ${key}`);
  }
}

// Export for use in other files (Service Worker compatible)
// For service workers, we need to use a different export method
if (typeof self !== 'undefined' && self.constructor.name === 'ServiceWorkerGlobalScope') {
  self.StorageIntegrityManager = StorageIntegrityManager;
} else if (typeof window !== 'undefined') {
  window.StorageIntegrityManager = StorageIntegrityManager;
}
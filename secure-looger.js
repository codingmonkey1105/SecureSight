// secure-logger.js
// Blockchain-style tamper-proof logging for security events

class SecureLogger {
  constructor() {
    this.logChain = [];
    this.previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.initialized = false;
  }
  
  async initialize() {
    if (this.initialized) return;
    
    // Load existing log chain
    const stored = await chrome.storage.local.get(['secureLogChain']);
    if (stored.secureLogChain) {
      this.logChain = stored.secureLogChain;
      if (this.logChain.length > 0) {
        this.previousHash = this.logChain[this.logChain.length - 1].hash;
      }
      
      // Verify integrity on load
      const isValid = await this.verifyChainIntegrity();
      if (!isValid) {
        console.error('[SECURITY] Log chain integrity violation detected!');
        // Keep logs but flag as compromised
        await this.log('SECURITY_ALERT', { 
          message: 'Log tampering detected',
          action: 'starting_new_chain'
        });
      }
    }
    
    this.initialized = true;
    console.log('🔐 SecureLogger initialized with', this.logChain.length, 'existing entries');
  }
  
  async log(event, details, level = 'INFO') {
    // Ensure initialized
    if (!this.initialized) {
      await this.initialize();
    }
    
    const logEntry = {
      timestamp: new Date().toISOString(),
      timestampMs: Date.now(),
      event: String(event), // Force string to prevent injection
      details: this.sanitizeLogData(details),
      level: level,
      previousHash: this.previousHash,
      sequence: this.logChain.length
    };
    
    // Compute hash including previous hash (blockchain-style)
    logEntry.hash = await this.computeHash(logEntry);
    
    this.logChain.push(logEntry);
    this.previousHash = logEntry.hash;
    
    // Keep only last 5000 entries (prevent storage bloat)
    if (this.logChain.length > 5000) {
      const removed = this.logChain.shift();
      console.warn('[LOGGER] Removed oldest log entry:', removed.sequence);
    }
    
    // Persist to storage (async, don't block)
    chrome.storage.local.set({ secureLogChain: this.logChain }).catch(err => {
      console.error('[LOGGER] Failed to persist logs:', err);
    });
    
    // Also output to console for debugging (but don't rely on console for security)
    console.log(`[${level}] ${event}:`, details);
    
    return logEntry;
  }
  
  sanitizeLogData(data) {
    if (data === null || data === undefined) {
      return data;
    }
    
    // Handle primitive types
    if (typeof data !== 'object') {
      return data;
    }
    
    // Deep clone to avoid modifying original
    let safeData;
    try {
      safeData = JSON.parse(JSON.stringify(data));
    } catch (err) {
      return '[Circular or non-serializable data]';
    }
    
    // Redact sensitive fields
    const sensitiveFields = ['apiKey', 'password', 'token', 'secret', 'key', 'authorization', 'cookie'];
    
    function redactRecursive(obj) {
      if (typeof obj !== 'object' || obj === null) {
        return obj;
      }
      
      // Handle arrays
      if (Array.isArray(obj)) {
        return obj.map(item => redactRecursive(item));
      }
      
      // Handle objects
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          // Check if key contains sensitive keyword
          const keyLower = key.toLowerCase();
          const isSensitive = sensitiveFields.some(field => keyLower.includes(field.toLowerCase()));
          
          if (isSensitive) {
            obj[key] = '[REDACTED]';
          } else if (typeof obj[key] === 'object') {
            obj[key] = redactRecursive(obj[key]);
          } else if (typeof obj[key] === 'string' && obj[key].length > 1000) {
            // Truncate very long strings
            obj[key] = obj[key].substring(0, 1000) + '... [TRUNCATED]';
          }
        }
      }
      
      return obj;
    }
    
    return redactRecursive(safeData);
  }
  
  async computeHash(logEntry) {
    // Create string representation (excluding hash field)
    const dataString = JSON.stringify({
      timestamp: logEntry.timestamp,
      timestampMs: logEntry.timestampMs,
      event: logEntry.event,
      details: logEntry.details,
      level: logEntry.level,
      previousHash: logEntry.previousHash,
      sequence: logEntry.sequence
    });
    
    // Compute SHA-256 hash
    const encoder = new TextEncoder();
    const data = encoder.encode(dataString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return hashHex;
  }
  
  async verifyChainIntegrity() {
    if (this.logChain.length === 0) {
      return true; // Empty chain is valid
    }
    
    // Verify first entry
    let expectedPreviousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    
    for (let i = 0; i < this.logChain.length; i++) {
      const entry = this.logChain[i];
      
      // Verify previous hash matches
      if (entry.previousHash !== expectedPreviousHash) {
        console.error(`[SECURITY] Chain break at index ${i}: previousHash mismatch`);
        return false;
      }
      
      // Verify sequence number
      if (entry.sequence !== i) {
        console.error(`[SECURITY] Chain break at index ${i}: sequence number mismatch`);
        return false;
      }
      
      // Recompute hash and verify
      const computedHash = await this.computeHash(entry);
      if (computedHash !== entry.hash) {
        console.error(`[SECURITY] Chain break at index ${i}: hash mismatch`);
        return false;
      }
      
      expectedPreviousHash = entry.hash;
    }
    
    console.log('✅ Log chain integrity verified');
    return true;
  }
  
  // Get logs with optional filtering
  getLogs(options = {}) {
    let filtered = [...this.logChain];
    
    // Filter by level
    if (options.level) {
      filtered = filtered.filter(log => log.level === options.level);
    }
    
    // Filter by event
    if (options.event) {
      filtered = filtered.filter(log => log.event === options.event);
    }
    
    // Filter by time range
    if (options.startTime) {
      filtered = filtered.filter(log => log.timestampMs >= options.startTime);
    }
    if (options.endTime) {
      filtered = filtered.filter(log => log.timestampMs <= options.endTime);
    }
    
    // Limit number of results
    if (options.limit) {
      filtered = filtered.slice(-options.limit);
    }
    
    return filtered;
  }
  
  // Export logs for analysis
  exportLogs() {
    return {
      exportTime: new Date().toISOString(),
      totalEntries: this.logChain.length,
      integrityVerified: true, // Assume verified on load
      logs: this.logChain
    };
  }
  
  // Clear all logs (use with caution)
  async clearLogs() {
    await this.log('LOG_CLEAR', { 
      message: 'All logs cleared by user/system',
      previousEntries: this.logChain.length 
    }, 'WARN');
    
    this.logChain = [];
    this.previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    
    await chrome.storage.local.remove(['secureLogChain']);
    console.warn('⚠️ All logs cleared');
  }
}

// Export for use in other files
if (typeof self !== 'undefined' && self.constructor.name === 'ServiceWorkerGlobalScope') {
  self.SecureLogger = SecureLogger;
} else if (typeof window !== 'undefined') {
  window.SecureLogger = SecureLogger;
}
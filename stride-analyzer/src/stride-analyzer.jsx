import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Upload, RefreshCw } from 'lucide-react';

export default function STRIDEAnalyzer() {
  const [files, setFiles] = useState({});
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);

  // Auto-load files if they exist in the conversation
  useEffect(() => {
    loadFilesFromContext();
  }, []);

  const loadFilesFromContext = async () => {
    setLoading(true);
    const fileMap = {};
    
    const filesToLoad = [
      'manifest.json',
      'popup.js',
      'STRIDE.simple.js',
      'popup.html'
    ];

    for (const filename of filesToLoad) {
      try {
        const content = await window.fs.readFile(filename, { encoding: 'utf8' });
        fileMap[filename] = content;
      } catch (err) {
        console.log(`Could not load ${filename}`);
      }
    }

    if (Object.keys(fileMap).length > 0) {
      setFiles(fileMap);
      analyzeFiles(fileMap);
    }
    setLoading(false);
  };

  const handleFileUpload = (e) => {
    const uploadedFiles = Array.from(e.target.files);
    const fileMap = { ...files };

    uploadedFiles.forEach(file => {
      const reader = new FileReader();
      reader.onload = (event) => {
        fileMap[file.name] = event.target.result;
        setFiles({ ...fileMap });
        analyzeFiles(fileMap);
      };
      reader.readAsText(file);
    });
  };

  const analyzeFiles = (fileMap) => {
    setLoading(true);
    
    const threats = {
      spoofing: [],
      tampering: [],
      repudiation: [],
      informationDisclosure: [],
      denialOfService: [],
      privilegeEscalation: []
    };

    let manifest = null;
    let jsCode = '';
    let htmlCode = '';

    // Parse files
    Object.entries(fileMap).forEach(([name, content]) => {
      if (name === 'manifest.json') {
        try {
          manifest = JSON.parse(content);
        } catch (e) {
          console.error('Failed to parse manifest.json');
        }
      } else if (name.endsWith('.js')) {
        jsCode += content + '\n';
      } else if (name.endsWith('.html')) {
        htmlCode += content + '\n';
      }
    });

    // SPOOFING Analysis
    const apiKeyRegex = /(api[_-]?key|apikey|api_token|access[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_-]{20,})["']/gi;
    const apiKeyMatches = [...jsCode.matchAll(apiKeyRegex)];
    if (apiKeyMatches.length > 0) {
      threats.spoofing.push({
        name: 'Exposed API Key',
        score: 10,
        details: `Found ${apiKeyMatches.length} hardcoded API key(s) in code`,
        severity: 'critical'
      });
    } else {
      threats.spoofing.push({
        name: 'API Key Management',
        score: 0,
        details: 'No hardcoded API keys detected',
        severity: 'safe'
      });
    }

    // Check for extension ID verification
    if (jsCode.includes('chrome.runtime.onMessage') || jsCode.includes('chrome.runtime.onMessageExternal')) {
      const hasIdCheck = jsCode.includes('sender.id') || jsCode.includes('chrome.runtime.id');
      if (!hasIdCheck && jsCode.includes('onMessageExternal')) {
        threats.spoofing.push({
          name: 'No Extension Verification',
          score: 7,
          details: 'External messages accepted without sender verification',
          severity: 'high'
        });
      } else {
        threats.spoofing.push({
          name: 'Extension Verification',
          score: hasIdCheck ? 0 : 2,
          details: hasIdCheck ? 'Sender verification implemented' : 'Limited verification',
          severity: hasIdCheck ? 'safe' : 'low'
        });
      }
    }

    // TAMPERING Analysis
    const hasValidation = jsCode.includes('validate') || jsCode.includes('sanitize') || jsCode.includes('DOMPurify');
    if (jsCode.includes('chrome.runtime.onMessage') && !hasValidation) {
      threats.tampering.push({
        name: 'Unvalidated Message Handlers',
        score: 9,
        details: 'Message handlers accept data without validation',
        severity: 'critical'
      });
    } else if (jsCode.includes('chrome.runtime.onMessage')) {
      threats.tampering.push({
        name: 'Message Handler Validation',
        score: hasValidation ? 0 : 5,
        details: hasValidation ? 'Input validation present' : 'Limited validation',
        severity: hasValidation ? 'safe' : 'medium'
      });
    }

    // Check storage usage
    const usesLocalStorage = jsCode.includes('localStorage') || jsCode.includes('sessionStorage');
    const usesChromeStorage = jsCode.includes('chrome.storage');
    if (usesLocalStorage) {
      threats.tampering.push({
        name: 'Unsafe Storage',
        score: 6,
        details: 'Using localStorage (unencrypted, accessible to content scripts)',
        severity: 'high'
      });
    } else if (usesChromeStorage) {
      threats.tampering.push({
        name: 'Storage Security',
        score: 2,
        details: 'Using chrome.storage API (better isolation)',
        severity: 'low'
      });
    }

    // URL sanitization check
    const hasSanitization = jsCode.includes('encodeURI') || jsCode.includes('URL(') || jsCode.includes('sanitize');
    if ((jsCode.includes('favicon') || jsCode.includes('getFavicon')) && !hasSanitization) {
      threats.tampering.push({
        name: 'No URL Sanitization',
        score: 7,
        details: 'Favicon/URL handling without sanitization',
        severity: 'high'
      });
    } else if (jsCode.includes('favicon')) {
      threats.tampering.push({
        name: 'URL Sanitization',
        score: 0,
        details: 'URL handling includes sanitization',
        severity: 'safe'
      });
    }

    // REPUDIATION Analysis
    const hasLogging = jsCode.includes('console.log') || jsCode.includes('logger');
    const hasErrorTracking = jsCode.includes('catch') || jsCode.includes('try');
    
    threats.repudiation.push({
      name: 'Audit Logging',
      score: hasLogging ? 2 : 5,
      details: hasLogging ? 'Basic logging present' : 'No audit trail',
      severity: hasLogging ? 'low' : 'medium'
    });

    threats.repudiation.push({
      name: 'Error Tracking',
      score: hasErrorTracking ? 0 : 3,
      details: hasErrorTracking ? 'Error handling implemented' : 'No error tracking',
      severity: hasErrorTracking ? 'safe' : 'low'
    });

    // INFORMATION DISCLOSURE Analysis
    if (jsCode.includes('chrome.history') || jsCode.includes('tabs.query')) {
      threats.informationDisclosure.push({
        name: 'Browsing History Access',
        score: 9,
        details: 'Extension accesses browsing history/tabs',
        severity: 'critical'
      });
    }

    if (apiKeyMatches.length > 0) {
      threats.informationDisclosure.push({
        name: 'API Key in Network Traffic',
        score: 7,
        details: 'Hardcoded keys may be transmitted',
        severity: 'high'
      });
    }

    const hasConsoleLogs = (jsCode.match(/console\.log/g) || []).length;
    if (hasConsoleLogs > 5) {
      threats.informationDisclosure.push({
        name: 'Console Logging',
        score: 5,
        details: `${hasConsoleLogs} console.log statements (may leak sensitive data)`,
        severity: 'medium'
      });
    } else if (hasConsoleLogs > 0) {
      threats.informationDisclosure.push({
        name: 'Console Logging',
        score: 2,
        details: 'Minimal console logging',
        severity: 'low'
      });
    }

    // DENIAL OF SERVICE Analysis
    const hasRateLimiting = jsCode.includes('rateLimit') || jsCode.includes('throttle') || jsCode.includes('debounce');
    if ((jsCode.includes('fetch') || jsCode.includes('XMLHttpRequest')) && !hasRateLimiting) {
      threats.denialOfService.push({
        name: 'Excessive API Requests',
        score: 7,
        details: 'No rate limiting on network requests',
        severity: 'high'
      });
    } else if (jsCode.includes('fetch')) {
      threats.denialOfService.push({
        name: 'API Rate Limiting',
        score: 2,
        details: 'Rate limiting implemented',
        severity: 'low'
      });
    }

    if (jsCode.includes('MutationObserver') && !jsCode.includes('disconnect')) {
      threats.denialOfService.push({
        name: 'Memory Leak Risk',
        score: 5,
        details: 'MutationObserver without cleanup',
        severity: 'medium'
      });
    } else if (jsCode.includes('MutationObserver')) {
      threats.denialOfService.push({
        name: 'Observer Management',
        score: 0,
        details: 'Proper cleanup implemented',
        severity: 'safe'
      });
    }

    const hasRecursion = jsCode.includes('querySelectorAll') && jsCode.includes('forEach');
    if (hasRecursion) {
      threats.denialOfService.push({
        name: 'Link Scanning',
        score: 3,
        details: 'Potential performance impact from scanning',
        severity: 'low'
      });
    }

    // PRIVILEGE ESCALATION Analysis
    if (manifest) {
      const permissions = manifest.permissions || [];
      const hostPermissions = manifest.host_permissions || [];
      
      const riskyPerms = ['tabs', 'history', 'cookies', 'webRequest', 'webRequestBlocking'];
      const hasRiskyPerms = permissions.filter(p => riskyPerms.includes(p));
      
      if (hasRiskyPerms.length > 2) {
        threats.privilegeEscalation.push({
          name: 'Excessive Permissions',
          score: 7,
          details: `Multiple sensitive permissions: ${hasRiskyPerms.join(', ')}`,
          severity: 'high'
        });
      } else if (hasRiskyPerms.length > 0) {
        threats.privilegeEscalation.push({
          name: 'Permission Usage',
          score: 3,
          details: `Limited permissions: ${hasRiskyPerms.join(', ')}`,
          severity: 'low'
        });
      }

      const hasAllUrls = hostPermissions.some(p => p.includes('<all_urls>') || p === 'https://*/*');
      if (hasAllUrls) {
        threats.privilegeEscalation.push({
          name: 'Content Script on All Pages',
          score: 6,
          details: 'Extension can run on all websites',
          severity: 'high'
        });
      }

      const hasCSP = manifest.content_security_policy !== undefined;
      if (!hasCSP) {
        threats.privilegeEscalation.push({
          name: 'No CSP',
          score: 5,
          details: 'Content Security Policy not defined',
          severity: 'medium'
        });
      } else {
        threats.privilegeEscalation.push({
          name: 'CSP Configuration',
          score: 0,
          details: 'Content Security Policy configured',
          severity: 'safe'
        });
      }
    }

    const hasInnerHTML = jsCode.includes('.innerHTML') || jsCode.includes('insertAdjacentHTML');
    if (hasInnerHTML && !hasSanitization) {
      threats.privilegeEscalation.push({
        name: 'Script Injection Risk',
        score: 7,
        details: 'innerHTML usage without sanitization',
        severity: 'high'
      });
    } else if (hasInnerHTML) {
      threats.privilegeEscalation.push({
        name: 'DOM Manipulation',
        score: 2,
        details: 'Sanitized DOM manipulation',
        severity: 'low'
      });
    }

    setAnalysis(threats);
    setLoading(false);
  };

  const calculateTotals = () => {
    if (!analysis) return { total: 0, max: 190, percentage: 0, counts: {} };

    let total = 0;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };

    Object.values(analysis).forEach(category => {
      category.forEach(threat => {
        total += threat.score;
        if (threat.score === 0) counts.safe++;
        else if (threat.score >= 9) counts.critical++;
        else if (threat.score >= 6) counts.high++;
        else if (threat.score >= 4) counts.medium++;
        else counts.low++;
      });
    });

    const max = 190; // Approximate max based on typical threat counts
    const percentage = Math.round((total / max) * 100);

    return { total, max, percentage, counts };
  };

  const getRiskLevel = (percentage) => {
    if (percentage >= 76) return { text: 'CRITICAL', color: 'critical' };
    if (percentage >= 51) return { text: 'HIGH', color: 'high' };
    if (percentage >= 26) return { text: 'MEDIUM', color: 'medium' };
    return { text: 'LOW', color: 'low' };
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#e74c3c',
      high: '#e67e22',
      medium: '#f1c40f',
      low: '#3498db',
      safe: '#2ecc71'
    };
    return colors[severity] || '#95a5a6';
  };

  const { total, max, percentage, counts } = calculateTotals();
  const risk = getRiskLevel(percentage);

  return (
    <div style={{ 
      fontFamily: '"Segoe UI", system-ui, sans-serif',
      backgroundColor: '#0a0e27',
      color: '#fff',
      minHeight: '100vh',
      padding: '40px 20px'
    }}>
      <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <h1 style={{ color: '#9b84ff', fontSize: '34px', margin: '0 0 10px 0' }}>
            STRIDE Dynamic Security Analyzer
          </h1>
          <p style={{ color: '#aaa', margin: 0 }}>
            Real-time threat detection for SecureSight Extension
          </p>
        </div>

        {/* File Upload Section */}
        <div style={{
          background: '#1a1f3a',
          borderRadius: '14px',
          padding: '25px',
          marginBottom: '20px',
          textAlign: 'center'
        }}>
          <label htmlFor="fileUpload" style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '10px',
            padding: '12px 24px',
            background: '#9b84ff',
            color: '#000',
            borderRadius: '8px',
            cursor: 'pointer',
            fontWeight: '600'
          }}>
            <Upload size={20} />
            Upload Extension Files
          </label>
          <input
            id="fileUpload"
            type="file"
            multiple
            accept=".js,.json,.html"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
          <button
            onClick={loadFilesFromContext}
            style={{
              marginLeft: '10px',
              padding: '12px 24px',
              background: '#6ea0ff',
              color: '#000',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              fontWeight: '600',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '10px'
            }}
          >
            <RefreshCw size={20} />
            Re-analyze Files
          </button>
          <p style={{ color: '#999', marginTop: '15px', fontSize: '14px' }}>
            Loaded: {Object.keys(files).join(', ') || 'No files loaded'}
          </p>
        </div>

        {loading && (
          <div style={{ textAlign: 'center', padding: '40px', color: '#9b84ff' }}>
            <RefreshCw size={48} style={{ animation: 'spin 1s linear infinite' }} />
            <p>Analyzing security threats...</p>
          </div>
        )}

        {analysis && !loading && (
          <>
            {/* Summary Card */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-around',
              alignItems: 'center',
              background: '#1a1f3a',
              borderRadius: '14px',
              padding: '25px',
              marginBottom: '20px',
              flexWrap: 'wrap',
              gap: '20px'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                <div style={{
                  width: '50px',
                  height: '50px',
                  borderRadius: '50%',
                  background: getSeverityColor(risk.color),
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}>
                  {risk.text === 'LOW' ? <CheckCircle size={28} /> : <AlertTriangle size={28} />}
                </div>
                <div>
                  <h2 style={{ 
                    margin: 0, 
                    fontSize: '32px',
                    color: getSeverityColor(risk.color)
                  }}>
                    {risk.text}
                  </h2>
                  <p style={{ color: '#bbb', margin: '5px 0 0' }}>Risk Level</p>
                </div>
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '32px' }}>{total}</h2>
                <p style={{ color: '#bbb', margin: '5px 0 0' }}>Total Score / {max}</p>
              </div>
              <div>
                <h2 style={{ 
                  margin: 0, 
                  fontSize: '32px',
                  color: getSeverityColor(risk.color)
                }}>
                  {percentage}%
                </h2>
                <p style={{ color: '#bbb', margin: '5px 0 0' }}>Risk Percentage</p>
              </div>
              <div>
                <h2 style={{ margin: 0, fontSize: '32px' }}>
                  {Object.values(analysis).reduce((sum, cat) => sum + cat.length, 0)}
                </h2>
                <p style={{ color: '#bbb', margin: '5px 0 0' }}>Threats Analyzed</p>
              </div>
            </div>

            {/* Risk Tags */}
            <div style={{ textAlign: 'center', margin: '15px 0 25px' }}>
              <span style={{
                padding: '6px 14px',
                borderRadius: '8px',
                margin: '0 5px',
                fontSize: '15px',
                background: '#2ecc71',
                color: '#000',
                fontWeight: '600'
              }}>
                🟢 Safe: {counts.safe}
              </span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '8px',
                margin: '0 5px',
                fontSize: '15px',
                background: '#3498db',
                color: '#000',
                fontWeight: '600'
              }}>
                🔵 Low: {counts.low}
              </span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '8px',
                margin: '0 5px',
                fontSize: '15px',
                background: '#f1c40f',
                color: '#000',
                fontWeight: '600'
              }}>
                🟡 Medium: {counts.medium}
              </span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '8px',
                margin: '0 5px',
                fontSize: '15px',
                background: '#e67e22',
                color: '#000',
                fontWeight: '600'
              }}>
                🟠 High: {counts.high}
              </span>
              <span style={{
                padding: '6px 14px',
                borderRadius: '8px',
                margin: '0 5px',
                fontSize: '15px',
                background: '#e74c3c',
                color: '#000',
                fontWeight: '600'
              }}>
                🔴 Critical: {counts.critical}
              </span>
            </div>

            {/* Threat Categories */}
            {Object.entries(analysis).map(([category, threats]) => {
              const categoryScore = threats.reduce((sum, t) => sum + t.score, 0);
              const categoryMax = threats.length * 10;
              const categoryPercent = Math.round((categoryScore / categoryMax) * 100);
              
              const categoryNames = {
                spoofing: 'Spoofing',
                tampering: 'Tampering',
                repudiation: 'Repudiation',
                informationDisclosure: 'Information Disclosure',
                denialOfService: 'Denial of Service',
                privilegeEscalation: 'Privilege Escalation'
              };

              return (
                <div key={category} style={{
                  background: '#1a1f3a',
                  borderRadius: '12px',
                  padding: '20px',
                  marginBottom: '20px'
                }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '10px'
                  }}>
                    <h3 style={{ color: '#9b84ff', margin: 0 }}>
                      {categoryNames[category]}
                    </h3>
                    <span style={{ color: '#ccc' }}>
                      Score: {categoryScore}/{categoryMax}
                    </span>
                  </div>
                  <div style={{
                    height: '8px',
                    background: '#111428',
                    borderRadius: '5px',
                    marginBottom: '15px',
                    overflow: 'hidden'
                  }}>
                    <div style={{
                      width: `${categoryPercent}%`,
                      height: '100%',
                      background: '#6ea0ff',
                      borderRadius: '5px'
                    }} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {threats.map((threat, idx) => (
                      <div key={idx} style={{
                        background: '#2a2148',
                        border: `2px solid ${getSeverityColor(threat.severity)}`,
                        borderRadius: '8px',
                        padding: '10px 14px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}>
                        <div>
                          <div style={{ fontWeight: '600' }}>
                            {threat.score === 0 ? '✅' : '❌'} {threat.name}
                          </div>
                          <div style={{ fontSize: '13px', color: '#aaa', marginTop: '4px' }}>
                            {threat.details}
                          </div>
                        </div>
                        <span style={{ 
                          fontWeight: '600',
                          color: getSeverityColor(threat.severity),
                          fontSize: '16px'
                        }}>
                          {threat.score}/10
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}

            {/* Risk Level Guide */}
            <div style={{
              background: '#1a1f3a',
              borderRadius: '12px',
              padding: '20px',
              marginTop: '40px'
            }}>
              <h4 style={{ color: '#9b84ff', marginTop: 0 }}>Risk Level Guide</h4>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '15px'
              }}>
                {[
                  { level: 'LOW', range: '0–25%', color: '#2ecc71', bg: '#0c2716', desc: 'Minimal security concerns' },
                  { level: 'MEDIUM', range: '26–50%', color: '#f1c40f', bg: '#3a2e00', desc: 'Some vulnerabilities present' },
                  { level: 'HIGH', range: '51–75%', color: '#e67e22', bg: '#3b2200', desc: 'Significant security risks' },
                  { level: 'CRITICAL', range: '76–100%', color: '#e74c3c', bg: '#2d0f0f', desc: 'Immediate action required' }
                ].map(item => (
                  <div key={item.level} style={{
                    background: item.bg,
                    border: `2px solid ${item.color}`,
                    borderRadius: '10px',
                    padding: '15px',
                    textAlign: 'center'
                  }}>
                    <div style={{ 
                      fontSize: '18px', 
                      fontWeight: '600',
                      color: item.color,
                      marginBottom: '5px'
                    }}>
                      {item.level} ({item.range})
                    </div>
                    <p style={{ margin: '5px 0 0', fontSize: '14px', color: '#bbb' }}>
                      {item.desc}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

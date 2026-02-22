import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SSRFProtection } from '../../../src/utils/ssrf-protection';
import { validateInstanceContext } from '../../../src/types/instance-context';

describe('SSRFProtection.validateUrlSync', () => {
  const originalEnv = process.env.N8N_API_SECURITY_MODE;

  afterEach(() => {
    if (originalEnv) {
      process.env.N8N_API_SECURITY_MODE = originalEnv;
    } else {
      delete process.env.N8N_API_SECURITY_MODE;
    }
  });

  describe('Default Mode (Permissive)', () => {
    beforeEach(() => {
      delete process.env.N8N_API_SECURITY_MODE;
    });

    it('should allow localhost', () => {
      const result = SSRFProtection.validateUrlSync('http://localhost:5678');
      expect(result.valid).toBe(true);
    });

    it('should allow private IPs', () => {
      const result = SSRFProtection.validateUrlSync('http://192.168.1.1:5678');
      expect(result.valid).toBe(true);
    });

    it('should block cloud metadata', () => {
      const result = SSRFProtection.validateUrlSync('http://169.254.169.254/latest/meta-data');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Cloud metadata');
    });
  });

  describe('Strict Mode', () => {
    beforeEach(() => {
      process.env.N8N_API_SECURITY_MODE = 'strict';
    });

    it('should block localhost', () => {
      const result = SSRFProtection.validateUrlSync('http://localhost:5678');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Localhost');
    });

    it('should block private IPs', () => {
      const result = SSRFProtection.validateUrlSync('http://192.168.1.1:5678');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Private IP');
    });

    it('should allow public URLs', () => {
      const result = SSRFProtection.validateUrlSync('https://api.n8n.io');
      expect(result.valid).toBe(true);
    });
  });

  describe('Moderate Mode', () => {
    beforeEach(() => {
      process.env.N8N_API_SECURITY_MODE = 'moderate';
    });

    it('should allow localhost', () => {
      const result = SSRFProtection.validateUrlSync('http://localhost:5678');
      expect(result.valid).toBe(true);
    });

    it('should block private IPs', () => {
      const result = SSRFProtection.validateUrlSync('http://10.0.0.1:5678');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Private IP');
    });
  });

  describe('Protocol Validation', () => {
    it('should block non-http protocols', () => {
      const result = SSRFProtection.validateUrlSync('ftp://example.com');
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('protocol');
    });
  });
});

describe('InstanceContext Validation Integration', () => {
  it('should use SSRFProtection for n8nApiUrl', () => {
    const context = {
      n8nApiUrl: 'http://169.254.169.254/metadata', // Cloud metadata
      n8nApiKey: 'valid-api-key-1234567890abcdef'
    };

    const result = validateInstanceContext(context);
    expect(result.valid).toBe(false);
    expect(result.errors).toBeDefined();
    expect(result.errors![0]).toContain('Cloud metadata endpoint blocked');
  });

  it('should allow valid URLs in default mode', () => {
    const context = {
      n8nApiUrl: 'http://localhost:5678', // Localhost allowed by default
      n8nApiKey: 'valid-api-key-1234567890abcdef'
    };

    const result = validateInstanceContext(context);
    expect(result.valid).toBe(true);
  });
});

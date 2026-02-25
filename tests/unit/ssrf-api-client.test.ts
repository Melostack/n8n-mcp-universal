import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios from 'axios';
import { N8nApiClient } from '../../src/services/n8n-api-client';

// Hoist the mock function so it can be used in vi.mock factory
const { validateWebhookUrlMock } = vi.hoisted(() => {
  return { validateWebhookUrlMock: vi.fn() };
});

// Mock SSRFProtection
vi.mock('../../src/utils/ssrf-protection', () => ({
  SSRFProtection: {
    validateWebhookUrl: validateWebhookUrlMock,
  },
}));

// Mock axios
vi.mock('axios', () => {
  // Store handlers in a closure variable that persists across calls
  const handlers: any[] = [];

  const client = {
    interceptors: {
      request: {
        use: (onFulfilled: any, onRejected: any) => {
          handlers.push({ onFulfilled, onRejected });
          return handlers.length - 1;
        },
      },
      response: {
        use: () => {},
      },
    },
    defaults: { baseURL: '' },
    get: () => Promise.resolve({}),
    post: () => Promise.resolve({}),

    // Helper methods for testing
    _triggerRequest: async (config: any) => {
      let promise = Promise.resolve(config);
      for (const handler of handlers) {
        if (handler.onFulfilled) {
          try {
            promise = promise.then(handler.onFulfilled);
          } catch (e) {
            return Promise.reject(e);
          }
        }
      }
      return promise;
    },
    _clearHandlers: () => {
      handlers.length = 0;
    }
  };

  return {
    default: {
      create: () => client,
    },
  };
});

describe('N8nApiClient SSRF Protection', () => {
  let mockClient: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // access the mocked client
    mockClient = axios.create();
    if (mockClient._clearHandlers) {
      mockClient._clearHandlers();
    }
  });

  it('should enable SSRF protection when validateBaseUrl is true', async () => {
    // Create client - this adds the interceptor
    new N8nApiClient({
      baseUrl: 'https://api.n8n.cloud',
      apiKey: 'test-key',
      validateBaseUrl: true,
    });

    // Mock successful validation
    validateWebhookUrlMock.mockResolvedValue({ valid: true });

    // Simulate request
    const config = { url: '/workflows', baseURL: 'https://api.n8n.cloud/api/v1' };
    await mockClient._triggerRequest(config);

    expect(validateWebhookUrlMock).toHaveBeenCalledWith('https://api.n8n.cloud/api/v1/workflows');
  });

  it('should block request when SSRF validation fails', async () => {
    new N8nApiClient({
      baseUrl: 'http://localhost:5678',
      apiKey: 'test-key',
      validateBaseUrl: true,
    });

    // Mock failed validation
    validateWebhookUrlMock.mockResolvedValue({ valid: false, reason: 'Localhost not allowed' });

    const config = { url: '/workflows', baseURL: 'http://localhost:5678/api/v1' };

    await expect(mockClient._triggerRequest(config))
      .rejects.toThrow(/SSRF Protection: Blocked request/);
  });

  it('should NOT enable SSRF protection when validateBaseUrl is false', async () => {
    new N8nApiClient({
      baseUrl: 'https://api.n8n.cloud',
      apiKey: 'test-key',
      validateBaseUrl: false,
    });

    const config = { url: '/workflows', baseURL: 'https://api.n8n.cloud/api/v1' };

    await mockClient._triggerRequest(config);

    expect(validateWebhookUrlMock).not.toHaveBeenCalled();
  });

  it('should handle absolute URLs correctly', async () => {
    new N8nApiClient({
      baseUrl: 'https://api.n8n.cloud',
      apiKey: 'test-key',
      validateBaseUrl: true,
    });

    validateWebhookUrlMock.mockResolvedValue({ valid: true });

    const config = { url: 'https://other-domain.com/api', baseURL: 'https://api.n8n.cloud/api/v1' };

    await mockClient._triggerRequest(config);

    expect(validateWebhookUrlMock).toHaveBeenCalledWith('https://other-domain.com/api');
  });

  it('should handle URL without leading slash correctly', async () => {
    new N8nApiClient({
      baseUrl: 'https://api.n8n.cloud',
      apiKey: 'test-key',
      validateBaseUrl: true,
    });

    validateWebhookUrlMock.mockResolvedValue({ valid: true });

    const config = { url: 'workflows', baseURL: 'https://api.n8n.cloud/api/v1' };

    await mockClient._triggerRequest(config);

    // Should add slash
    expect(validateWebhookUrlMock).toHaveBeenCalledWith('https://api.n8n.cloud/api/v1/workflows');
  });
});

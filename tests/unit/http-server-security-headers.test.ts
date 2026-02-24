import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SingleSessionHTTPServer } from '../../src/http-server-single-session';

// Mock dependencies
vi.mock('../../src/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn()
  }
}));

vi.mock('dotenv');

vi.mock('uuid', () => ({
  v4: vi.fn(() => 'test-session-id-1234-5678-9012-345678901234')
}));

// Mock minimal dependencies to avoid errors
vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: vi.fn().mockImplementation(() => ({
    handleRequest: vi.fn(),
    close: vi.fn().mockResolvedValue(undefined)
  }))
}));

vi.mock('@modelcontextprotocol/sdk/server/sse.js', () => ({
  SSEServerTransport: vi.fn().mockImplementation(() => ({
    close: vi.fn().mockResolvedValue(undefined)
  }))
}));

vi.mock('../../src/mcp/server', () => ({
  N8NDocumentationMCPServer: vi.fn().mockImplementation(() => ({
    connect: vi.fn().mockResolvedValue(undefined)
  }))
}));

const mockConsoleManager = {
  wrapOperation: vi.fn().mockImplementation(async (fn: () => Promise<any>) => {
    return await fn();
  })
};

vi.mock('../../src/utils/console-manager', () => ({
  ConsoleManager: vi.fn(() => mockConsoleManager)
}));

vi.mock('../../src/utils/url-detector', () => ({
  getStartupBaseUrl: vi.fn((host: string, port: number) => `http://localhost:${port || 3000}`),
  formatEndpointUrls: vi.fn((baseUrl: string) => ({
    health: `${baseUrl}/health`,
    mcp: `${baseUrl}/mcp`
  })),
  detectBaseUrl: vi.fn((req: any, host: string, port: number) => `http://localhost:${port || 3000}`)
}));

vi.mock('../../src/utils/version', () => ({
  PROJECT_VERSION: '2.8.3'
}));

// Create handlers storage for Express mock
const mockHandlers: { [key: string]: any[] } = {
  get: [],
  post: [],
  delete: [],
  use: []
};

// Mock Express with focus on middleware and settings
vi.mock('express', () => {
  const mockExpressApp = {
    get: vi.fn((path: string, ...handlers: any[]) => {
      mockHandlers.get.push({ path, handlers });
      return mockExpressApp;
    }),
    post: vi.fn((path: string, ...handlers: any[]) => {
      mockHandlers.post.push({ path, handlers });
      return mockExpressApp;
    }),
    delete: vi.fn((path: string, ...handlers: any[]) => {
      mockHandlers.delete.push({ path, handlers });
      return mockExpressApp;
    }),
    use: vi.fn((handler: any) => {
      mockHandlers.use.push(handler);
      return mockExpressApp;
    }),
    set: vi.fn(),
    disable: vi.fn(), // Mock disable method
    listen: vi.fn((port: number, host: string, callback?: () => void) => {
      if (callback) callback();
      return {
        on: vi.fn(),
        close: vi.fn((cb: () => void) => cb()),
        address: () => ({ port: 3000 })
      };
    })
  };

  interface ExpressMock {
    (): typeof mockExpressApp;
    json(): (req: any, res: any, next: any) => void;
  }

  const expressMock = vi.fn(() => mockExpressApp) as unknown as ExpressMock;
  expressMock.json = vi.fn(() => (req: any, res: any, next: any) => {
    req.body = req.body || {};
    next();
  });

  return {
    default: expressMock,
    Request: {},
    Response: {},
    NextFunction: {}
  };
});

describe('HTTP Server Security Headers', () => {
  const originalEnv = process.env;
  const TEST_AUTH_TOKEN = 'test-auth-token-with-more-than-32-characters';
  let server: SingleSessionHTTPServer;

  beforeEach(() => {
    process.env = { ...originalEnv };
    process.env.AUTH_TOKEN = TEST_AUTH_TOKEN;
    process.env.PORT = '0';
    process.env.NODE_ENV = 'test';

    // Reset mocks
    vi.clearAllMocks();
    mockHandlers.get = [];
    mockHandlers.post = [];
    mockHandlers.delete = [];
    mockHandlers.use = [];
  });

  afterEach(async () => {
    process.env = originalEnv;
    if (server) {
      await server.shutdown();
    }
  });

  function createMockReqRes() {
    const headers: { [key: string]: string } = {};
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
      setHeader: vi.fn((key: string, value: string) => {
        headers[key.toLowerCase()] = value;
      }),
      sendStatus: vi.fn().mockReturnThis(),
      headersSent: false,
      finished: false,
      statusCode: 200,
      getHeader: (key: string) => headers[key.toLowerCase()],
      headers
    };

    const req = {
      method: 'GET',
      path: '/',
      url: '/',
      headers: {} as Record<string, string>,
      body: {},
      ip: '127.0.0.1',
      get: vi.fn((header: string) => (req.headers as Record<string, string>)[header.toLowerCase()])
    };

    return { req, res };
  }

  it('should disable x-powered-by header', async () => {
    // Import express to get access to the mock
    const express = await import('express');
    const app = express.default(); // This gets the mocked app instance

    server = new SingleSessionHTTPServer();
    await server.start();

    // Verify app.disable('x-powered-by') was called
    expect(app.disable).toHaveBeenCalledWith('x-powered-by');
  });

  it('should set security headers', async () => {
    server = new SingleSessionHTTPServer();
    await server.start();

    const { req, res } = createMockReqRes();

    // Find security headers middleware
    // It's usually one of the first middlewares
    let securityMiddlewareFound = false;

    for (const middleware of mockHandlers.use) {
      // Only execute standard middleware (req, res, next), skip error handlers (err, req, res, next)
      if (typeof middleware === 'function' && middleware.length < 4) {
        const next = vi.fn();
        await middleware(req, res, next);

        // Check if this middleware set security headers
        if (res.setHeader.mock.calls.some((call: any[]) => call[0] === 'X-Content-Type-Options')) {
          securityMiddlewareFound = true;

          // Verify headers
          expect(res.headers['x-content-type-options']).toBe('nosniff');
          expect(res.headers['x-frame-options']).toBe('DENY');
          expect(res.headers['x-xss-protection']).toBe('1; mode=block');
          expect(res.headers['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');

          // Verify Content-Security-Policy (the new requirement)
          expect(res.headers['content-security-policy']).toBe("default-src 'none'; frame-ancestors 'none';");
        }
      }
    }

    expect(securityMiddlewareFound).toBe(true);
  });
});

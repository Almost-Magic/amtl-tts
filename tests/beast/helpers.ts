/**
 * Beast Test Helpers — shared utilities for all Beast test suites.
 */
import { createApp } from '../../src/app.js';
import type { Express } from 'express';

export interface TestResponse {
  status: number;
  body: Record<string, unknown>;
}

let cachedApp: Express | null = null;

export function getTestApp(): Express {
  if (!cachedApp) {
    cachedApp = createApp();
  }
  return cachedApp;
}

export function resetTestApp(): void {
  cachedApp = null;
}

/**
 * Make a request to the test app without starting a real server.
 */
export async function request(
  app: Express,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: Record<string, unknown>,
): Promise<TestResponse> {
  return new Promise((resolve) => {
    const { createServer } = require('http');
    const server = createServer(app);

    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      const url = `http://127.0.0.1:${port}${path}`;

      const options: RequestInit = {
        method,
        headers: { 'Content-Type': 'application/json' },
      };
      if (body && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(body);
      }

      fetch(url, options)
        .then(async (res) => {
          const json = await res.json().catch(() => ({}));
          server.close();
          resolve({ status: res.status, body: json as Record<string, unknown> });
        })
        .catch(() => {
          server.close();
          resolve({ status: 500, body: { error: 'Request failed' } });
        });
    });
  });
}

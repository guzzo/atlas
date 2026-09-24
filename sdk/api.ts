// Generated route types plus a typed HTTP client for outside-party integrations.
import createClient from 'openapi-fetch';
import type { paths } from './generated.js';
export function registryClient(baseUrl: string, adminToken?: string) {
  return createClient<paths>({
    baseUrl,
    headers: adminToken ? { Authorization: `Bearer ${adminToken}` } : {},
  });
}

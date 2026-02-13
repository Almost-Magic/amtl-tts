/**
 * Shared types used across all Digital Sentinel modules.
 */

export interface Organisation {
  id: string;
  name: string;
  industry: string;
  geography: string;
  size: 'small' | 'medium' | 'large' | 'enterprise';
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cvssScore: number;
  cveId?: string;
  findingType: string;
  description: string;
  affectedAsset: string;
  discoveredAt: string;
  resolvedAt?: string;
  exposureDays: number;
  mitreTechniques?: string[];
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

export function apiSuccess<T>(data: T): ApiResponse<T> {
  return {
    success: true,
    data,
    timestamp: new Date().toISOString(),
  };
}

export function apiError(error: string): ApiResponse {
  return {
    success: false,
    error,
    timestamp: new Date().toISOString(),
  };
}

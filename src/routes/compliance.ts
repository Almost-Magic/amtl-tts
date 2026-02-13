/**
 * Milestone 20: Compliance Autopilot — Routes
 */
import { Router } from 'express';
import { apiSuccess, apiError } from '../models/shared.js';
import * as service from '../services/compliance.js';

export function complianceRoutes(): Router {
  const router = Router();

  // POST /api/compliance/assess/:org — run compliance assessment
  router.post('/assess/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { posture, frameworks } = req.body;

      if (!posture) {
        res.status(400).json(apiError('Missing required field: posture'));
        return;
      }

      const assessment = service.runFullAssessment(org, posture, frameworks);
      res.json(apiSuccess(assessment));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/compliance/essential-eight/:org — Essential Eight status
  router.post('/essential-eight/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { posture } = req.body;

      if (!posture) {
        res.status(400).json(apiError('Missing required field: posture'));
        return;
      }

      const e8 = service.getEssentialEightStatus(org, posture);
      res.json(apiSuccess(e8));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/compliance/gaps/:org — gap analysis
  router.post('/gaps/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { posture } = req.body;

      if (!posture) {
        res.status(400).json(apiError('Missing required field: posture'));
        return;
      }

      const gaps = service.getGapAnalysis(org, posture);
      res.json(apiSuccess(gaps));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // POST /api/compliance/report/:org — generate compliance report
  router.post('/report/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { posture } = req.body;

      if (!posture) {
        res.status(400).json(apiError('Missing required field: posture'));
        return;
      }

      const report = service.generateComplianceReport(org, posture);
      res.json(apiSuccess(report));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/compliance/frameworks — list supported frameworks
  router.get('/frameworks', (_req, res) => {
    const frameworks = service.listFrameworks();
    res.json(apiSuccess(frameworks));
  });

  return router;
}

/**
 * Milestone 19: Threat Actor Profiler — Routes
 */
import { Router } from 'express';
import { apiSuccess, apiError } from '../models/shared.js';
import * as service from '../services/threat-actor.js';

export function threatActorRoutes(): Router {
  const router = Router();

  // POST /api/threat-actors/profile/:org — generate threat actor profile
  router.post('/profile/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { vulnerabilities, industry, geography } = req.body;

      if (!vulnerabilities || !industry || !geography) {
        res.status(400).json(apiError('Missing required fields: vulnerabilities, industry, geography'));
        return;
      }

      const profile = service.profileOrganisation(org, vulnerabilities, industry, geography);
      res.json(apiSuccess(profile));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/threat-actors/mapping/:org — MITRE ATT&CK mapping
  router.post('/mapping/:org', (req, res) => {
    try {
      const { vulnerabilities } = req.body;
      if (!vulnerabilities) {
        res.status(400).json(apiError('Missing required field: vulnerabilities'));
        return;
      }

      const mappings = service.getMitreMapping(vulnerabilities);
      res.json(apiSuccess(mappings));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/threat-actors/killchain/:org — kill chain analysis
  router.post('/killchain/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { vulnerabilities } = req.body;

      if (!vulnerabilities) {
        res.status(400).json(apiError('Missing required field: vulnerabilities'));
        return;
      }

      const analysis = service.getKillChainAnalysis(org, vulnerabilities);
      res.json(apiSuccess(analysis));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/threat-actors/briefing/:org — executive briefing
  router.post('/briefing/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { vulnerabilities, industry, geography } = req.body;

      if (!vulnerabilities || !industry || !geography) {
        res.status(400).json(apiError('Missing required fields: vulnerabilities, industry, geography'));
        return;
      }

      const briefing = service.getExecutiveBriefing(org, vulnerabilities, industry, geography);
      res.json(apiSuccess(briefing));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  return router;
}

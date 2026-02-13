/**
 * Milestone 17: Autonomous Remediation Policy Framework — Routes
 */
import { Router } from 'express';
import { apiSuccess, apiError } from '../models/shared.js';
import * as service from '../services/remediation-policy.js';

export function remediationPolicyRoutes(): Router {
  const router = Router();

  // GET /api/policy/remediation — list all policies
  router.get('/remediation', (_req, res) => {
    const policies = service.listPolicies();
    res.json(apiSuccess(policies));
  });

  // POST /api/policy/remediation — create/update policy
  router.post('/remediation', (req, res) => {
    try {
      const { findingType, tier, description, remediationAction, yamlContent } = req.body;

      if (yamlContent) {
        const policies = service.loadPoliciesFromYaml(yamlContent);
        res.status(201).json(apiSuccess(policies));
        return;
      }

      if (!findingType || !tier || !description || !remediationAction) {
        res.status(400).json(apiError('Missing required fields: findingType, tier, description, remediationAction'));
        return;
      }

      const policy = service.createOrUpdatePolicy({ findingType, tier, description, remediationAction });
      res.status(201).json(apiSuccess(policy));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // POST /api/policy/remediation/trigger — trigger remediation for a finding
  router.post('/remediation/trigger', (req, res) => {
    try {
      const { findingType, description, notificationEmail } = req.body;
      if (!findingType) {
        res.status(400).json(apiError('Missing required field: findingType'));
        return;
      }
      const action = service.triggerRemediation({ findingType, description, notificationEmail });
      res.status(201).json(apiSuccess(action));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // POST /api/policy/approve/:action_id — approve queued action
  router.post('/approve/:action_id', (req, res) => {
    try {
      const { action_id } = req.params;
      const { approvalToken, approvedBy } = req.body;

      if (!approvalToken || !approvedBy) {
        res.status(400).json(apiError('Missing required fields: approvalToken, approvedBy'));
        return;
      }

      const action = service.approveAction(action_id, approvalToken, approvedBy);
      res.json(apiSuccess(action));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // POST /api/policy/halt — emergency halt all auto-remediation
  router.post('/halt', (req, res) => {
    const { haltedBy, reason } = req.body;
    const state = service.emergencyHalt(
      haltedBy ?? 'unknown',
      reason ?? 'Emergency halt activated',
    );
    res.json(apiSuccess(state));
  });

  // GET /api/policy/audit — audit trail
  router.get('/audit', (_req, res) => {
    const log = service.getAuditLog();
    res.json(apiSuccess(log));
  });

  return router;
}

import express from 'express';
import { remediationPolicyRoutes } from './routes/remediation-policy.js';
import { breachForecastRoutes } from './routes/breach-forecast.js';
import { threatActorRoutes } from './routes/threat-actor.js';
import { complianceRoutes } from './routes/compliance.js';

export function createApp(): express.Express {
  const app = express();

  app.use(express.json());

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'operational', service: 'Digital Sentinel', version: '3.0.0' });
  });

  // Milestone 17: Autonomous Remediation Policy Framework
  app.use('/api/policy', remediationPolicyRoutes());

  // Milestone 18: Probabilistic Breach Forecasting
  app.use('/api/forecast', breachForecastRoutes());

  // Milestone 19: Threat Actor Profiler
  app.use('/api/threat-actors', threatActorRoutes());

  // Milestone 20: Compliance Autopilot
  app.use('/api/compliance', complianceRoutes());

  return app;
}

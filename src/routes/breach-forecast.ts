/**
 * Milestone 18: Probabilistic Breach Forecasting — Routes
 */
import { Router } from 'express';
import { apiSuccess, apiError } from '../models/shared.js';
import * as service from '../services/breach-forecast.js';

export function breachForecastRoutes(): Router {
  const router = Router();

  // POST /api/forecast/calculate/:org — calculate breach probability
  router.post('/calculate/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { inventory, industry, simulationRuns, seed } = req.body;

      if (!inventory) {
        res.status(400).json(apiError('Missing required field: inventory'));
        return;
      }

      const forecast = service.calculateForecast(org, inventory, industry, simulationRuns, seed);
      res.json(apiSuccess(forecast));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // POST /api/forecast/whatif/:org — run what-if scenario
  router.post('/whatif/:org', (req, res) => {
    try {
      const { org } = req.params;
      const { inventory, remediations, industry, simulationRuns, seed } = req.body;

      if (!inventory || !remediations) {
        res.status(400).json(apiError('Missing required fields: inventory, remediations'));
        return;
      }

      const scenario = service.whatIfScenario(org, inventory, remediations, industry, simulationRuns, seed);
      res.json(apiSuccess(scenario));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json(apiError(message));
    }
  });

  // GET /api/forecast/history/:org — probability trend over time
  router.get('/history/:org', (req, res) => {
    const { org } = req.params;
    const history = service.getForecastHistory(org);
    res.json(apiSuccess(history));
  });

  // GET /api/forecast/factors/:org — contributing risk factors
  router.get('/factors/:org', (req, res) => {
    const { org } = req.params;
    const factors = service.getRiskFactors(org);
    res.json(apiSuccess(factors));
  });

  return router;
}

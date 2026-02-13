/**
 * Abstracted clock for testability.
 */
export const clock = {
  now(): Date {
    return new Date();
  },
  isoNow(): string {
    return new Date().toISOString();
  },
};

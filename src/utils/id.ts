import { v4 as uuidv4 } from 'uuid';

export function generateId(): string {
  return uuidv4();
}

export function generateToken(): string {
  return uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');
}

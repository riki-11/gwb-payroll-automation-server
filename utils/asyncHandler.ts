// utils/asyncHandler.ts
import { RequestHandler } from 'express';

// TODO: Double check whether this is necessary or not.

export const asyncHandler = (fn: (...args: any[]) => Promise<any>): RequestHandler =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

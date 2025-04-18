// middleware/authMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import { sql, poolPromise } from '../db';
import { asyncHandler } from '../utils/asyncHandler';

// Extend Express Request type to include user property
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        name: string;
        email: string;
        role: string;
      };
      accessToken?: string;
    }
  }
}

// Middleware to check authentication with session cookie
// TODO: remove try-catch?
const authMiddleware =  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  try {
    const sessionId = req.cookies.user_session;

    if (!sessionId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Get session from database
    const pool = await poolPromise;
    const sessionResult = await pool.request()
      .input('session_id', sql.VarChar, sessionId)
      .query(`
        SELECT s.*, u.id as user_id, u.name, u.email, u.role
        FROM UserSessions s
        JOIN Users u ON s.user_id = u.id
        WHERE s.session_id = @session_id AND s.expires_at > GETDATE()
      `);

    if (sessionResult.recordset.length === 0) {
      // Session not found or expired
      res.clearCookie('user_session');
      return res.status(401).json({ error: 'Session expired or invalid' });
    }

    const session = sessionResult.recordset[0];

    // Set user info on request for use in route handlers
    req.user = {
      id: session.user_id,
      name: session.name,
      email: session.email,
      role: session.role
    };

    // Also provide the access token for Microsoft API calls if needed
    req.accessToken = session.access_token;

    // Extend session expiry time (optional)
    await pool.request()
      .input('session_id', sql.VarChar, sessionId)
      .input('expires_at', sql.DateTime, new Date(Date.now() + 24 * 60 * 60 * 1000)) // 24 hours from now
      .query('UPDATE UserSessions SET expires_at = @expires_at WHERE session_id = @session_id');

    next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    res.status(500).json({ error: 'Authentication check failed' });
  }
});

// Middleware to check for specific roles
const requireRole = (roles: string | string[]) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];
  
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
};

export { authMiddleware, requireRole };
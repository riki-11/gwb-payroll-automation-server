// Updated auth.ts for storing Microsoft tokens
import express, { Request, Response } from 'express';
import { ConfidentialClientApplication } from '@azure/msal-node';
import { sql, poolPromise } from '../db';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import * as cookie from 'cookie';
import { asyncHandler } from '../utils/asyncHandler';

dotenv.config();

const router = express.Router();

// MSAL configuration
const msalConfig = {
  auth: {
    clientId: process.env.MICROSOFT_CLIENT_ID!,
    authority: `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}`,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET!,
  },
};

const msalClient = new ConfidentialClientApplication(msalConfig);

// Determine environment
const isProduction = process.env.NODE_ENV === 'production';

const redirectUri = isProduction
  ? process.env.OAUTH_REDIRECT_URI_PROD!
  : process.env.OAUTH_REDIRECT_URI_LOCAL!;

const frontendOrigin = isProduction
  ? process.env.FRONTEND_ORIGIN_PROD!
  : process.env.FRONTEND_ORIGIN_LOCAL!;

// Microsoft login - start the flow
router.get('/auth/login',  asyncHandler( async (req: Request, res: Response) => {
  try {
    // Create a server-side session ID
    const sessionId = uuidv4();
    
    // Generate the auth URL
    const authUrl = await msalClient.getAuthCodeUrl({
      scopes: process.env.OAUTH_SCOPES!.split(' '),
      redirectUri,
      state: sessionId // Pass the session ID as state to retrieve it later
    });

    // Store the session ID in a secure cookie
    res.setHeader('Set-Cookie', cookie.serialize('auth_session', sessionId, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60, // 1 hour in seconds
    }));
    

    // Redirect to Microsoft login
    res.redirect(authUrl);
  } catch (error) {
    console.error('Error generating auth URL:', error);
    res.status(500).send('Authentication initialization failed');
  }
}));

// Handle the callback
router.get('/auth/callback', asyncHandler( async (req: Request, res: Response) => {
  const authCode = req.query.code as string;
  const stateFromCallback = req.query.state as string;

  const cookies = cookie.parse(req.headers.cookie || '');
  const sessionId = cookies.auth_session;
  

  // Verify state matches to prevent CSRF
  if (!stateFromCallback || stateFromCallback !== sessionId) {
    return res.status(400).send('Invalid state parameter');
  }

  if (!authCode) {
    return res.status(400).send('Authorization code missing');
  }

  try {
    // Exchange auth code for tokens
    const tokenResponse = await msalClient.acquireTokenByCode({
      code: authCode,
      scopes: process.env.OAUTH_SCOPES!.split(' '),
      redirectUri,
    });

    // Extract access token and user information
    const accessToken = tokenResponse.accessToken;
    const userName = tokenResponse.account?.name || '';
    const userEmail = tokenResponse.account?.username || '';
    const msalAccountId = tokenResponse.account?.homeAccountId || '';

    // Get SQL pool
    const pool = await poolPromise;

    // Check if user exists in database
    const userCheckResult = await pool.request()
      .input('email', sql.VarChar, userEmail)
      .query('SELECT * FROM Users WHERE email = @email');

    let userId;

    if (userCheckResult.recordset.length === 0) {
      // User doesn't exist, create them
      const userInsertResult = await pool.request()
        .input('name', sql.VarChar, userName)
        .input('email', sql.VarChar, userEmail)
        .input('msal_account_id', sql.VarChar, msalAccountId)
        .query(`
          INSERT INTO Users (name, email, msal_account_id, role)
          VALUES (@name, @email, @msal_account_id, 'user');
          SELECT SCOPE_IDENTITY() AS id;
        `);
      
      userId = userInsertResult.recordset[0].id;
    } else {
      userId = userCheckResult.recordset[0].id;
      
      // Update existing user's MSAL account ID if needed
      if (userCheckResult.recordset[0].msal_account_id !== msalAccountId) {
        await pool.request()
          .input('id', sql.Int, userId)
          .input('msal_account_id', sql.VarChar, msalAccountId)
          .query('UPDATE Users SET msal_account_id = @msal_account_id WHERE id = @id');
      }
    }

    // Create a server-side session
    const serverSessionId = uuidv4();
    
    // Store token in database with session ID
    await pool.request()
      .input('session_id', sql.VarChar, serverSessionId)
      .input('user_id', sql.Int, userId)
      .input('access_token', sql.VarChar, accessToken)
      .input('expires_at', sql.DateTime, new Date(Date.now() + 3600 * 1000)) // 1 hour from now
      .query(`
        INSERT INTO UserSessions (session_id, user_id, access_token, expires_at)
        VALUES (@session_id, @user_id, @access_token, @expires_at)
      `);

    // Set secure session cookie with just the session ID (not the token)
    res.setHeader('Set-Cookie', cookie.serialize('user_session', serverSessionId, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 24 * 60 * 60, // 24 hours
    }));
    

    // Redirect to frontend with successful login
    res.redirect(`${frontendOrigin}/`);
  } catch (error) {
    console.error('Error during token acquisition:', error);
    res.status(500).send('Authentication failed');
  }
}));

// Get current user
router.get('/auth/current-user', asyncHandler( async (req: Request, res: Response) => {
  const cookies = cookie.parse(req.headers.cookie || '');
  const sessionId = cookies.user_session;

  
  if (!sessionId) {
    return res.status(401).json({ isAuthenticated: false });
  }

  try {
    // Get session from database
    const pool = await poolPromise;
    const sessionResult = await pool.request()
      .input('session_id', sql.VarChar, sessionId)
      .query(`
        SELECT s.*, u.name, u.email, u.role
        FROM UserSessions s
        JOIN Users u ON s.user_id = u.id
        WHERE s.session_id = @session_id AND s.expires_at > GETDATE()
      `);

    if (sessionResult.recordset.length === 0) {
      // Session not found or expired
      res.setHeader('Set-Cookie', cookie.serialize('user_session', '', {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/',
        expires: new Date(0),
      }));
      

      return res.status(401).json({ isAuthenticated: false });
    }

    const userSession = sessionResult.recordset[0];
    
    // Return user info without the token
    res.json({
      isAuthenticated: true,
      user: {
        id: userSession.user_id,
        name: userSession.name,
        email: userSession.email,
        role: userSession.role
      }
    });
  } catch (error) {
    console.error('Error getting current user:', error);
    res.status(500).json({ error: 'Failed to authenticate user' });
  }
}));

// Logout 
router.get('/auth/logout', asyncHandler( async (req: Request, res: Response) => {
  try {
    const cookies = cookie.parse(req.headers.cookie || '');
    const sessionId = cookies.user_session;


    if (sessionId) {
      // Remove session from database
      const pool = await poolPromise;
      await pool.request()
        .input('session_id', sql.VarChar, sessionId)
        .query('DELETE FROM UserSessions WHERE session_id = @session_id');
      
      // Clear the cookie
      res.setHeader('Set-Cookie', cookie.serialize('user_session', '', {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/',
        expires: new Date(0),
      }));
      
    }
    
    // Redirect to Microsoft logout endpoint, then back to homepage
    const logoutUrl = `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}/oauth2/v2.0/logout`;
    res.redirect(`${logoutUrl}?post_logout_redirect_uri=${frontendOrigin}`);
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).send('Logout failed');
  }
}));

export default router;
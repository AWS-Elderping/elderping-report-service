// authMiddleware.js
// Shared middleware logic for authentication, role mapping, permissions checking, and relationship verification

const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
const { Pool } = require('pg');
const { ROLE_PERMISSIONS } = require('./permissions');

const cognitoUserPoolId = process.env.COGNITO_USER_POOL_ID;
const awsRegion = process.env.AWS_REGION || 'us-east-1';
const jwksUri = `https://cognito-idp.${awsRegion}.amazonaws.com/${cognitoUserPoolId}/.well-known/jwks.json`;

const client = cognitoUserPoolId ? jwksRsa({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  jwksUri: jwksUri
}) : null;

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) return callback(err);
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Global Auth Pool for local check if in users_db (auth-service)
let pool = null;
if (process.env.DB_NAME === 'users_db') {
  pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
}

// Map database roles to in-memory aliases: ELDER -> USER, FAMILY -> CAREGIVER
const mapRole = (role) => {
  const r = (role || '').toUpperCase();
  if (r === 'ELDER') return 'USER';
  if (r === 'FAMILY') return 'CAREGIVER';
  return r;
};

// Validate JWT and populate req.user (id, email, role)
const validateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header missing or malformed' });
  }

  const token = authHeader.split(' ')[1];

  // Service-to-Service authentication bypass using REPORT_SERVICE_TOKEN
  const reportServiceToken = process.env.REPORT_SERVICE_TOKEN || 'mock-report-service-token';
  if (token === reportServiceToken) {
    req.user = {
      id: 'SYSTEM',
      userId: 'SYSTEM',
      role: 'SUPER_ADMIN',
      email: 'system-report@elderpinq.com'
    };
    return next();
  }

  if (cognitoUserPoolId) {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
      if (err) return res.status(401).json({ error: 'Invalid or expired Cognito token' });
      const rawRole = decoded['custom:role'] || decoded.role || 'ELDER';
      req.user = {
        id: decoded.sub,
        userId: decoded.sub, // backward compatibility
        username: decoded['cognito:username'] || decoded.username,
        role: mapRole(rawRole),
        rawRole: rawRole, // preserve original role
        email: decoded.email
      };
      next();
    });
  } else {
    // Fallback to local JWT verification
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
      const rawRole = (decoded.role || 'ELDER').toUpperCase();
      req.user = {
        id: decoded.userId || decoded.id,
        userId: decoded.userId || decoded.id, // backward compatibility
        username: decoded.username,
        role: mapRole(rawRole),
        rawRole: rawRole, // preserve original role
        email: decoded.email
      };
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid or expired local token' });
    }
  }
};

// Require specified role (handles string or array of strings, maps aliases)
const requireRole = (roleOrRoles) => {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    
    const userRole = req.user.role; // already normalized
    const rolesArray = Array.isArray(roleOrRoles) ? roleOrRoles : [roleOrRoles];
    const normAllowedList = rolesArray.map(mapRole);
    
    if (normAllowedList.includes(userRole)) {
      next();
    } else {
      res.status(403).json({ error: 'Forbidden: Insufficient privileges' });
    }
  };
};

// Require at least one of the listed roles
const requireAnyRole = (roles) => {
  return requireRole(roles);
};

// Verify centralized permissions mappings
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    
    const userRole = req.user.role; // already normalized
    const permissions = ROLE_PERMISSIONS[userRole] || [];
    
    if (permissions.includes(permission)) {
      next();
    } else {
      res.status(403).json({ error: 'Forbidden: Insufficient privileges' });
    }
  };
};

// Relationship verification (ABAC for Caregiver-to-Elder access control)
const checkRelationship = (elderIdParam = 'elderId') => {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });

    const { id: userId, role } = req.user;
    
    // Resolve Elder ID from params, body, or query
    const elderId = req.params[elderIdParam] || req.body[elderIdParam] || req.query[elderIdParam];
    if (!elderId) {
      return res.status(400).json({ error: 'Elder ID is required for relationship verification' });
    }

    // Admins and Super Admins bypass checks
    if (role === 'SUPER_ADMIN' || role === 'ADMIN') {
      return next();
    }

    // Elder (USER) can only access their own data
    if (role === 'USER') {
      if (String(userId) === String(elderId)) {
        return next();
      } else {
        return res.status(403).json({ error: 'Forbidden: You cannot access other users records' });
      }
    }

    // Caregiver (CAREGIVER) must verify association links
    if (role === 'CAREGIVER') {
      try {
        const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://auth-service:3000';
        let linked = false;

        if (process.env.DB_NAME === 'users_db' && pool) {
          // If in auth-service, check table directly
          const result = await pool.query(
            'SELECT 1 FROM family_links WHERE family_id = $1 AND elder_id = $2',
            [userId, elderId]
          );
          linked = result.rows.length > 0;
        } else {
          // Cross-service call to auth-service verification route
          const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
          const response = await fetch(`${authServiceUrl}/links/verify/${userId}/${elderId}`);
          if (response.ok) {
            const data = await response.json();
            linked = data.linked;
          }
        }

        if (linked) {
          next();
        } else {
          res.status(403).json({ error: 'Forbidden: You are not linked to this elder' });
        }
      } catch (err) {
        console.error('Relationship validation error:', err.message);
        res.status(500).json({ error: 'Failed to verify relationship' });
      }
    } else {
      res.status(403).json({ error: 'Forbidden: Invalid role' });
    }
  };
};

module.exports = {
  validateToken,
  authenticate: validateToken, // authenticate alias
  requireRole,
  requireAnyRole,
  requirePermission,
  checkRelationship,
  mapRole
};

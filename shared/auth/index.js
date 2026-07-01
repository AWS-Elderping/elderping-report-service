// index.js
// Entrypoint for shared/auth package

const permissions = require('./permissions');
const authMiddleware = require('./authMiddleware');

/**
 * Asynchronously log audit event without blocking the API request-response cycle (fire-and-forget).
 * Supports dual signatures:
 *   1. logAuditEvent(req, eventData)
 *   2. logAuditEvent(eventData)
 * Includes timeout protection (2s) and one retry on transient failure.
 */
const logAuditEvent = (arg1, arg2) => {
  let actorId, actorEmail, actorRole, action, resource, resourceId, metadata, ipAddress, userAgent;
  let reqHeaderAuth = '';

  if (arg1 && arg1.headers) {
    // Old signature: logAuditEvent(req, eventData)
    const req = arg1;
    const data = arg2 || {};
    actorId = req.user?.id || req.user?.userId || 'SYSTEM';
    actorEmail = req.user?.email || 'system@elderpinq.com';
    actorRole = req.user?.role || 'SYSTEM';
    action = data.actionType || data.action || 'UNKNOWN';
    resource = data.resource || 'UNKNOWN';
    resourceId = data.resourceId || null;
    metadata = {
      status: data.status,
      message: data.message,
      beforeState: data.beforeState,
      afterState: data.afterState
    };
    ipAddress = req.headers?.['x-forwarded-for'] || req.socket?.remoteAddress || null;
    userAgent = req.headers?.['user-agent'] || null;
    reqHeaderAuth = req.headers?.authorization || '';
  } else {
    // New signature: logAuditEvent(eventData)
    const data = arg1 || {};
    actorId = data.actorId || 'SYSTEM';
    actorEmail = data.actorEmail || 'system@elderpinq.com';
    actorRole = data.actorRole || 'SYSTEM';
    action = data.action || 'UNKNOWN';
    resource = data.resource || 'UNKNOWN';
    resourceId = data.resourceId || null;
    metadata = data.metadata || {};
    ipAddress = data.ipAddress || null;
    userAgent = data.userAgent || null;
  }

  const payload = {
    actorId,
    actorEmail,
    actorRole,
    action,
    resource,
    resourceId,
    metadata,
    ipAddress,
    userAgent
  };

  let authHeader = '';
  if (process.env.AUDIT_SERVICE_TOKEN) {
    authHeader = `Bearer ${process.env.AUDIT_SERVICE_TOKEN}`;
  } else if (reqHeaderAuth) {
    authHeader = reqHeaderAuth;
  }

  // Non-blocking fire-and-forget background call
  const sendWithRetry = async (retriesLeft = 1) => {
    const auditServiceUrl = process.env.AUDIT_SERVICE_URL || 'http://audit-service:3000';
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000); // 2-second timeout

    try {
      const res = await fetch(`${auditServiceUrl}/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(authHeader ? { 'Authorization': authHeader } : {})
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!res.ok) {
        if (retriesLeft > 0) {
          console.warn(`[AUDIT HOOK WARNING] HTTP ${res.status} from audit service. Retrying...`);
          return sendWithRetry(retriesLeft - 1);
        } else {
          console.warn(`[AUDIT HOOK WARNING] Audit logging failed with HTTP status ${res.status} after retries.`);
        }
      }
    } catch (err) {
      clearTimeout(timeoutId);
      if (retriesLeft > 0) {
        console.warn(`[AUDIT HOOK WARNING] Error sending audit: ${err.message}. Retrying...`);
        return sendWithRetry(retriesLeft - 1);
      } else {
        console.warn(`[AUDIT HOOK WARNING] Final failure sending audit log: ${err.message}`);
      }
    }
  };

  sendWithRetry();
};

module.exports = {
  ...permissions,
  ...authMiddleware,
  logAuditEvent
};

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { validateToken, checkRelationship, requirePermission, logAuditEvent } = require('./authMiddleware');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// S3 Client configuration
const s3BucketName = process.env.REPORTS_S3_BUCKET || 'elderpinq-reports-bucket';
const awsRegion = process.env.AWS_REGION || 'us-east-1';
let s3Client = null;
try {
  s3Client = new S3Client({ region: awsRegion });
} catch (err) {
  console.log('⚠️ S3 Client could not initialize. Operating in mock mode.', err.message);
}

// Liveness probe (must be before path-rewrite middleware)
app.get('/health', (req, res) => res.status(200).json({ status: 'ok', service: 'report-service' }));
app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok', service: 'report-service' }));
app.get('/ready', (req, res) => res.status(200).json({ status: 'ok', service: 'report-service' }));

// K8s ALB path prefix compatibility: strip /api/reports prefix
app.use((req, _res, next) => {
  if (req.url.startsWith('/api/reports') || req.url.startsWith('/api/report')) {
    req.url = req.url.replace(/^\/api\/report[s]?/, '') || '/';
  }
  next();
});

// Helper to fetch microservices telemetry
async function fetchServiceData(url, token) {
  try {
    const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
    const response = await fetch(url, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (response.ok) return await response.json();
  } catch (err) {
    console.error(`Telemetry retrieval error for [${url}]:`, err.message);
  }
  return [];
}

// Report Ownership Validation Middleware
const verifyReportOwnership = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ error: 'Report ID is required' });
    }
    const reportRes = await pool.query('SELECT * FROM weekly_reports WHERE id = $1', [id]);
    if (reportRes.rows.length === 0) {
      return res.status(404).json({ error: 'Report profile not found' });
    }
    const report = reportRes.rows[0];
    req.report = report; // Cache for subsequent handlers

    const { id: userId, role } = req.user;

    // ADMIN/SUPER_ADMIN bypass
    if (role === 'SUPER_ADMIN' || role === 'ADMIN') {
      return next();
    }

    // Elder (USER) ownership check
    if (role === 'USER' || role === 'ELDER') {
      if (String(userId) === String(report.elder_id)) {
        return next();
      }
    }

    // Caregiver relationship check
    if (role === 'CAREGIVER' || role === 'FAMILY') {
      const authServiceUrl = process.env.AUTH_SERVICE_URL || 'http://auth-service:3000';
      const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
      const response = await fetch(`${authServiceUrl}/links/verify/${userId}/${report.elder_id}`);
      if (response.ok) {
        const data = await response.json();
        if (data.linked) {
          return next();
        }
      }
    }

    return res.status(403).json({ error: 'Forbidden: Access denied' });
  } catch (err) {
    console.error('verifyReportOwnership error:', err.message);
    res.status(500).json({ error: 'Internal server error verifying report ownership' });
  }
};

// Asynchronous Queue Logic
const jobQueue = [];
let processingQueue = false;

function enqueueJob(reportId, elderId, token) {
  jobQueue.push({ reportId, elderId, token });
  processQueue();
}

async function processQueue() {
  if (processingQueue) return;
  if (jobQueue.length === 0) return;
  processingQueue = true;

  const job = jobQueue.shift();
  try {
    await processReportJob(job.reportId, job.elderId, job.token);
  } catch (err) {
    console.error(`[QUEUE] Error processing report job ${job.reportId}:`, err.message);
  } finally {
    processingQueue = false;
    setImmediate(processQueue);
  }
}

async function processReportJob(reportId, elderId, token) {
  console.log(`[WORKER] Starting report generation job ${reportId} for elderId ${elderId}`);
  
  // Update status to GENERATING
  await pool.query('UPDATE weekly_reports SET status = \'GENERATING\' WHERE id = $1', [reportId]);

  try {
    // Internal URLs
    const healthUrl = `${process.env.HEALTH_SERVICE_URL || 'http://health-service:3000'}/vitals/${elderId}`;
    const reminderUrl = `${process.env.REMINDER_SERVICE_URL || 'http://reminder-service:3000'}/reminders/${elderId}/compliance`;
    const apptUrl = `${process.env.APPOINTMENT_SERVICE_URL || 'http://appointment-service:3000'}/appointments/elder/${elderId}`;
    const alertUrl = `${process.env.ALERT_SERVICE_URL || 'http://alert-service:3000'}/alerts/user/${elderId}`;
    const aiUrl = `${process.env.AI_SERVICE_URL || 'http://ai-service:3000'}/ai/query`;

    // Fetch Telemetry datasets in parallel
    const [vitals, compliance, appts, alerts] = await Promise.all([
      fetchServiceData(healthUrl, token),
      fetchServiceData(reminderUrl, token),
      fetchServiceData(apptUrl, token),
      fetchServiceData(alertUrl, token)
    ]);

    // Calculate metrics
    const totalMedicationsScheduled = compliance.length;
    const medicationsTakenCount = compliance.filter(c => c.status === 'TAKEN').length;
    const complianceRate = totalMedicationsScheduled > 0 ? (medicationsTakenCount / totalMedicationsScheduled) * 100 : 100.0;
    
    // Generate AI Insights via Bedrock
    let aiInsights = 'No metrics recorded. Maintain general caregiver oversight.';
    try {
      const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
      const aiResponse = await fetch(aiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          userId: elderId,
          capability: 'risk_analysis',
          query: `Vitals logged: ${JSON.stringify(vitals.slice(0, 5))}. Compliance: ${complianceRate}%. Alerts logged: ${alerts.length}. Please generate a risk summary.`
        })
      });
      if (aiResponse.ok) {
        const aiData = await aiResponse.json();
        aiInsights = aiData.result;
      }
    } catch (err) {
      console.error('Failed to retrieve AI insights:', err.message);
    }

    // Compile JSON Report Structure
    const reportData = {
      elderId,
      generatedAt: new Date().toISOString(),
      complianceRate: complianceRate.toFixed(2),
      vitalsTrend: vitals,
      appointments: appts,
      activeAlertsCount: alerts.filter(a => !a.is_resolved).length,
      aiInsights
    };

    // Calculate Composite Risk Score
    const riskScore = alerts.length > 5 ? 7.5 : (complianceRate < 70 ? 5.2 : 2.1);

    const s3Key = `reports/${elderId}/weekly-${Date.now()}.json`;

    // S3 upload fallback mock
    if (s3Client && process.env.AWS_ACCESS_KEY_ID) {
      await s3Client.send(new PutObjectCommand({
        Bucket: s3BucketName,
        Key: s3Key,
        Body: JSON.stringify(reportData, null, 2),
        ContentType: 'application/json'
      }));
    } else {
      console.log(`[MOCK] Uploaded report details to S3 Bucket: ${s3BucketName}, Key: ${s3Key}`);
    }

    // Update PG on completion
    await pool.query(
      `UPDATE weekly_reports 
       SET s3_bucket = $1, s3_key = $2, compliance_score = $3, health_risk_score = $4, status = 'COMPLETED'
       WHERE id = $5`,
      [s3BucketName, s3Key, complianceRate, riskScore, reportId]
    );

    // Call notification-service to trigger email automatically
    const notifServiceUrl = process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:3000';
    const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
    fetch(`${notifServiceUrl}/notifications/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({
        userId: elderId,
        type: 'WEEKLY_REPORT',
        payload: { reportId, s3Key }
      })
    }).catch(err => console.error('Failed to trigger report notification:', err.message));

    console.log(`[WORKER] Job ${reportId} finished successfully.`);
  } catch (error) {
    console.error(`[WORKER] Job ${reportId} failed during generation: ${error.message}`);
    
    // Increment retry count
    const retryRes = await pool.query(
      'UPDATE weekly_reports SET retry_count = retry_count + 1 WHERE id = $1 RETURNING retry_count',
      [reportId]
    );
    const newRetryCount = retryRes.rows[0]?.retry_count || 0;

    if (newRetryCount >= 5) {
      await pool.query('UPDATE weekly_reports SET status = \'FAILED\' WHERE id = $1', [reportId]);
      console.error(`[WORKER] Job ${reportId} failed permanently after 5 retries.`);
    } else {
      await pool.query('UPDATE weekly_reports SET status = \'PENDING\' WHERE id = $1', [reportId]);
      console.log(`[WORKER] Requeuing job ${reportId} (retry #${newRetryCount})`);
      enqueueJob(reportId, elderId, token);
    }
  }
}

// Startup Job Recovery
async function recoverJobs() {
  try {
    const result = await pool.query(
      `SELECT id, elder_id, retry_count FROM weekly_reports WHERE status IN ('PENDING', 'GENERATING')`
    );
    console.log(`[JOB RECOVERY] Found ${result.rows.length} unfinished report jobs on worker start.`);
    const systemToken = process.env.REPORT_SERVICE_TOKEN || 'mock-report-service-token';

    for (const row of result.rows) {
      if (row.retry_count >= 5) {
        await pool.query('UPDATE weekly_reports SET status = \'FAILED\' WHERE id = $1', [row.id]);
        console.log(`[JOB RECOVERY] Job ${row.id} exceeded retry limit. Set status to FAILED.`);
      } else {
        enqueueJob(row.id, row.elder_id, systemToken);
      }
    }
  } catch (err) {
    console.error('[JOB RECOVERY ERROR] Failed to recover unfinished jobs:', err.message);
  }
}

// Generate weekly report
app.post('/reports/generate', validateToken, requirePermission('REPORT_GENERATE'), checkRelationship('elderId'), async (req, res) => {
  try {
    const { elderId } = req.body;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (!elderId) return res.status(400).json({ error: 'elderId is required' });

    // Insert pending job record
    const result = await pool.query(
      `INSERT INTO weekly_reports (elder_id, status)
       VALUES ($1, 'PENDING') RETURNING *`,
      [elderId]
    );
    const report = result.rows[0];

    // Enqueue for background processing
    enqueueJob(report.id, elderId, token);

    // Audit Log
    logAuditEvent(req, {
      action: 'START_REPORT_GENERATION',
      resource: 'weekly_reports',
      resourceId: report.id,
      metadata: { status: 'SUCCESS', message: `Report generation job started for elder: ${elderId}` }
    });

    res.status(202).json({ id: report.id, status: 'PENDING' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fetch all reports generated for an elder
app.get('/reports/user/:elderId', validateToken, requirePermission('REPORT_READ'), checkRelationship('elderId'), async (req, res) => {
  try {
    const { elderId } = req.params;
    const result = await pool.query(
      'SELECT * FROM weekly_reports WHERE elder_id = $1 ORDER BY created_at DESC',
      [elderId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /reports/:id/status
app.get('/reports/:id/status', validateToken, requirePermission('REPORT_READ'), verifyReportOwnership, async (req, res) => {
  try {
    const report = req.report; // Cached by verifyReportOwnership middleware
    
    // Audit Log
    logAuditEvent(req, {
      action: 'VIEW_REPORT_STATUS',
      resource: 'weekly_reports',
      resourceId: report.id,
      metadata: { status: 'SUCCESS', message: `Report status viewed. Current status: ${report.status}` }
    });

    res.json({
      id: report.id,
      elderId: report.elder_id,
      status: report.status,
      retryCount: report.retry_count,
      complianceScore: report.compliance_score,
      riskScore: report.health_risk_score,
      createdAt: report.created_at
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Retrieve specific S3 Report download link
app.get('/reports/:id/download', validateToken, requirePermission('REPORT_READ'), verifyReportOwnership, async (req, res) => {
  try {
    const report = req.report; // Cached by verifyReportOwnership middleware

    if (report.status !== 'COMPLETED') {
      return res.status(400).json({ error: `Report is not ready for download. Current status: ${report.status}` });
    }

    // Audit Log
    logAuditEvent(req, {
      action: 'DOWNLOAD_REPORT',
      resource: 'weekly_reports',
      resourceId: report.id,
      metadata: { status: 'SUCCESS', message: `Report download link requested` }
    });

    res.json({
      id: report.id,
      elderId: report.elder_id,
      complianceScore: report.compliance_score,
      riskScore: report.health_risk_score,
      downloadUrl: `https://${report.s3_bucket}.s3.${awsRegion}.amazonaws.com/${report.s3_key}`,
      createdAt: report.created_at
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Report service running on port ${PORT}`);
  recoverJobs();
});

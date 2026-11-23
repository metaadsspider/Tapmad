'use strict';
/*
 * Vercel serverless function: GET /live/<token>/<path> → proxy + rewrite.
 * Reached via the /live/* → /api/live/* rewrite in vercel.json.
 */
const core = require('../_core.js');

module.exports = async (req, res) => {
  try {
    await core.handleLive(req, res);
  } catch (_) {
    if (!res.headersSent) { res.statusCode = 500; res.end('error'); }
    else try { res.destroy(); } catch (_) {}
  }
};

// If your Vercel plan allows longer function timeouts, uncomment the next line:
// module.exports.maxDuration = 60;

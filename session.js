'use strict';
/* Vercel serverless function: POST /api/session → issues a signed stream token. */
const core = require('./_core.js');

module.exports = async (req, res) => {
  try {
    await core.handleSession(req, res);
  } catch (_) {
    if (!res.headersSent) { res.statusCode = 500; res.end('error'); }
  }
};

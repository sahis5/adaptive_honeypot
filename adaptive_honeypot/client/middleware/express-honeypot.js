// client/middleware/express-honeypot.js
require('dotenv').config();
const axios = require('axios');

console.log("[HONEYPOT-MW] loaded");

const HONEYPOT_URL = process.env.HONEYPOT_URL || "http://127.0.0.1:5000/simulate_traffic";
const HONEYPOT_TIMEOUT_MS = parseInt(process.env.HONEYPOT_TIMEOUT_MS || "2000", 10);

function guessBodyString(req) {
  try {
    if (req.body && typeof req.body === 'string') return req.body;
    if (req.body && typeof req.body === 'object') return JSON.stringify(req.body);
  } catch (e) { /* ignore */ }
  if (req.rawBody) return req.rawBody.toString();
  return "";
}

function buildPayload(req) {
  const bodyStr = guessBodyString(req);
  return {
    src_ip: req.ip || req.headers['x-forwarded-for'] || "unknown",
    payload: (req.method === 'GET') ? (req.originalUrl || req.url) : bodyStr
  };
}

module.exports = function honeypotMiddleware(opts = {}) {
  return async function (req, res, next) {
    try {
      console.log("[HONEYPOT] incoming:", { method: req.method, url: req.originalUrl || req.url });

      const raw = guessBodyString(req);
      const urlLower = String(req.originalUrl || req.url || "").toLowerCase();
      const bodyLower = String(raw || "").toLowerCase();

      console.log("[HONEYPOT] headers content-type:", req.headers['content-type']);
      console.log("[HONEYPOT] body sample:", bodyLower.substring(0,200));

      const suspect =
           urlLower.includes("select") ||
           urlLower.includes("union") ||
           bodyLower.includes("select") ||
           bodyLower.includes("union") ||
           /insert|update|delete|drop|sql/i.test(bodyLower) ||
           ( (req.body && typeof req.body === 'object') &&
             Object.values(req.body).some(v => typeof v === 'string' && /select|union|insert|update|delete|drop|sql/i.test(v)) );

      console.log("[HONEYPOT] detect:", suspect);

      if (!suspect) return next();

      const payload = buildPayload(req);
      console.log("[HONEYPOT] calling backend:", HONEYPOT_URL, "payload:", payload);

      // use axios with timeout
      let resp = null;
      try {
        resp = await axios.post(HONEYPOT_URL, payload, { timeout: HONEYPOT_TIMEOUT_MS, headers: { 'Content-Type':'application/json' } });
      } catch (err) {
        if (err.code === 'ECONNABORTED') {
          console.error("[HONEYPOT] backend timeout");
        } else {
          console.error("[HONEYPOT] axios error:", err && err.message || err);
        }
        return next(); // fail-open
      }

      if (!resp || !resp.data) {
        console.log("[HONEYPOT] no data from backend -> allow request");
        return next();
      }

      const js = resp.data;
      console.log("[HONEYPOT] backend decision:", js);

      const ar = js.action_result || {};
      const action = (ar.action || ar.action_type || "normal").toString();
      // resolve redirect target to full backend URL if backend returned a relative path
      if (action === "redirect_honeypot" || action === "redirect") {
        let url = ar.url || "/honeypot/fakedb";

  // If URL is relative (starts with '/'), prepend HONEYPOT_BASE
        const HONEYPOT_BASE = process.env.HONEYPOT_BASE || "http://127.0.0.1:5000";
        if (typeof url === "string" && url.startsWith("/")) {
            url = HONEYPOT_BASE.replace(/\/$/, "") + url; // ensure no double slash
        }

        console.log("[HONEYPOT] redirecting to (resolved):", url);
  // perform a redirect to the backend honeypot endpoint
        return res.redirect(url);
      }

      if (action === "fake_data" || ar.fake) {
        console.log("[HONEYPOT] serve fake data");
        return res.status(200).json(ar.fake_payload || { fake: "simulated data" });
      }

      if (action === "tarpit" || action === "tarpit_slowdown" || action === "delay") {
        const d = parseInt(ar.delay_ms || 1000, 10);
        console.log("[HONEYPOT] tarpit sleep ms:", d);
        await new Promise(r=>setTimeout(r, d));
        return res.status(ar.status || 200).send(ar.message || "Slow down");
      }

    } catch (err) {
      console.error("[HONEYPOT] middleware error:", err && err.stack || err);
    }

    next();
  };
};

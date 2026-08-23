#!/usr/bin/env node
/**
 * Catches the dead localhost redirect that Codex, Claude Code, and Antigravity
 * send the browser to after approval, and forwards the authorization code to
 * this gateway's admin dashboard — so connecting a subscription seat never
 * needs the "copy the address bar, paste it into the dashboard" step.
 *
 * These vendors' desktop clients register a fixed loopback redirect that a
 * deployed Worker cannot receive (see docs/OAUTH_PROVIDERS.md). Approving
 * still sends the browser there; normally that page fails to load and you
 * copy the address out of the bar. This listens on that exact port instead,
 * grabs `code` and `state` off the request, and 302s the browser on to
 * /admin/dashboard with them in the query string. The dashboard already
 * completes the connection itself when it sees them (see the `boot()`
 * function in src/public/admin-dashboard.html) — nothing else to do.
 *
 * Usage:
 *   node scripts/oauth-catch.mjs codex https://ai-gateway.aditya-mer.workers.dev
 *   node scripts/oauth-catch.mjs claude http://localhost:8799
 *   node scripts/oauth-catch.mjs antigravity http://localhost:8799
 *
 * The gateway URL is required, not defaulted — this catcher redirects a live
 * browser tab there, and guessing wrong (e.g. sending a local-dev test at
 * prod) sends the OAuth code to the wrong deployment silently, where it
 * either 401s unnoticed or connects the seat on the wrong environment. GATEWAY_URL
 * works the same as the second argument if you'd rather set it once per shell.
 *
 * Run this *before* clicking "Authorize" in the dashboard. It handles one
 * redirect and exits.
 */

import { createServer } from 'node:http';

const VENDORS = {
  codex: { port: 1455, label: 'ChatGPT Codex' },
  claude: { port: 54545, label: 'Claude Code' },
  antigravity: { port: 51121, label: 'Antigravity' },
};

const vendorArg = process.argv[2];
const target = VENDORS[vendorArg];
const gatewayArg = process.argv[3] || process.env.GATEWAY_URL;

if (!target || !gatewayArg) {
  console.error('Usage: node scripts/oauth-catch.mjs <codex|claude|antigravity> <gateway-url>');
  console.error('\nCatches the vendor\'s dead localhost OAuth redirect and forwards it to the');
  console.error('gateway dashboard automatically, so you never copy-paste the failed URL by hand.');
  console.error('\nBoth arguments are required — get this wrong and the browser lands on the');
  console.error('wrong deployment with no visible error. Examples:');
  console.error('  node scripts/oauth-catch.mjs codex https://ai-gateway.aditya-mer.workers.dev');
  console.error('  node scripts/oauth-catch.mjs claude http://localhost:8799');
  process.exit(1);
}

let gatewayUrl;
try {
  gatewayUrl = new URL(gatewayArg);
} catch {
  console.error(`Invalid gateway URL: "${gatewayArg}"`);
  process.exit(1);
}
if (gatewayUrl.protocol !== 'http:' && gatewayUrl.protocol !== 'https:') {
  console.error(
    `Gateway URL must use http or https (got "${gatewayUrl.protocol}"). ` +
      'Did you forget the "//"? Example: node scripts/oauth-catch.mjs claude http://localhost:8799'
  );
  process.exit(1);
}

const gateway = gatewayUrl.toString().replace(/\/+$/, '/');

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${target.port}`);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (!code && !error) {
    // Not the callback (a favicon request, browser prefetch, etc). Ignore it
    // and keep listening for the real one.
    res.writeHead(404).end();
    return;
  }

  const dest = new URL('/admin/dashboard', gateway);
  if (error) {
    dest.searchParams.set(
      'oauth_error',
      url.searchParams.get('error_description') || error
    );
  } else {
    dest.searchParams.set('oauth_state', state || '');
    dest.searchParams.set('oauth_code', code);
  }

  res.writeHead(302, { Location: dest.toString() });
  res.end(
    `<!doctype html><meta charset="utf-8"><title>Redirecting&hellip;</title>` +
      `<p>Redirecting to the gateway dashboard&hellip; ` +
      `<a href="${dest.toString()}">click here</a> if it doesn't happen automatically. ` +
      `You can close this tab.</p>`
  );

  console.log(
    error
      ? `Authorization failed: ${error}. Forwarded to the dashboard.`
      : 'Authorization code caught — forwarded to the dashboard to finish the connection.'
  );

  // One redirect is the whole job; free the port immediately rather than
  // leaving a listener around to collide with the next run.
  server.close();
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(
      `Port ${target.port} is already in use. If a previous run of this script is ` +
        `still around, close it first.`
    );
  } else {
    console.error(err.message);
  }
  process.exit(1);
});

server.listen(target.port, '127.0.0.1', () => {
  console.log(`Listening on http://localhost:${target.port} for the ${target.label} redirect.`);
  console.log(`Forwarding to ${gateway}/admin/dashboard when it arrives.`);
  console.log('Now start the connection from the dashboard and approve in the browser.');
});

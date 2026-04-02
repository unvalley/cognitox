import http from "node:http";
import { URL } from "node:url";

const COGNITO_URL = "http://localhost:9229";
const CLIENT_ID = process.env.CLIENT_ID || "";
const REDIRECT_URI = "http://localhost:3000/callback";
const PORT = 3000;

// -------------------------------------------------------------------
// Security helpers
// -------------------------------------------------------------------

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// -------------------------------------------------------------------
// HTML helpers
// -------------------------------------------------------------------

function page(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - Cognitox Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #fafafa; color: #111; min-height: 100vh; display: flex; justify-content: center; padding: 48px 16px; }
    .container { max-width: 640px; width: 100%; }
    h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; }
    .subtitle { color: #666; font-size: 14px; margin-bottom: 32px; }
    .card { background: #fff; border: 1px solid #e5e5e5; border-radius: 8px; padding: 24px; margin-bottom: 16px; }
    .card h2 { font-size: 16px; font-weight: 600; margin-bottom: 16px; border-bottom: 1px solid #eee; padding-bottom: 8px; }
    .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f5f5f5; font-size: 14px; }
    .row:last-child { border-bottom: none; }
    .label { color: #666; min-width: 120px; }
    .value { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 13px; word-break: break-all; text-align: right; }
    .btn { display: inline-block; padding: 10px 24px; background: #111; color: #fff; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 500; border: none; cursor: pointer; transition: opacity 0.15s; }
    .btn:hover { opacity: 0.85; }
    .btn-outline { background: #fff; color: #111; border: 1px solid #ddd; }
    .btn-outline:hover { background: #f5f5f5; }
    .actions { display: flex; gap: 12px; margin-top: 24px; }
    .token-box { background: #f5f5f5; border: 1px solid #e5e5e5; border-radius: 4px; padding: 12px; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 11px; word-break: break-all; max-height: 80px; overflow-y: auto; margin-top: 8px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 12px; font-weight: 500; }
    .badge-green { background: #dcfce7; color: #166534; }
    .badge-gray { background: #f3f4f6; color: #374151; }
    .error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="container">
    ${body}
  </div>
</body>
</html>`;
}

// -------------------------------------------------------------------
// HTTP helpers
// -------------------------------------------------------------------

function sendHtml(res: http.ServerResponse, html: string, status = 200): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendJson(
  res: http.ServerResponse,
  data: unknown,
  status = 200
): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function getQueryParam(url: URL, key: string): string | null {
  return url.searchParams.get(key);
}

// -------------------------------------------------------------------
// Route handlers
// -------------------------------------------------------------------

function handleHome(res: http.ServerResponse): void {
  if (!CLIENT_ID) {
    sendHtml(
      res,
      page(
        "Setup Required",
        `
      <h1>Cognitox Demo App</h1>
      <p class="subtitle">A sample app demonstrating OAuth login with Cognitox</p>
      <div class="error">
        <strong>CLIENT_ID not set.</strong><br><br>
        Start with: <code>CLIENT_ID=your_client_id pnpm dev</code><br><br>
        You can find the Client ID in the <a href="http://localhost:9229/admin/">Cognitox Admin Console</a>.
      </div>
    `
      )
    );
    return;
  }

  const loginUrl = `${COGNITO_URL}/ui/?response_type=code&client_id=${encodeURIComponent(CLIENT_ID)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid+email+profile`;

  sendHtml(
    res,
    page(
      "Home",
      `
    <h1>Cognitox Demo App</h1>
    <p class="subtitle">A sample app demonstrating OAuth login with Cognitox</p>

    <div class="card">
      <h2>Welcome</h2>
      <p style="font-size: 14px; color: #666; margin-bottom: 16px;">
        Click the button below to sign in via the Cognitox Hosted UI.
        You'll be redirected back here with your tokens after authentication.
      </p>
      <a href="${escapeHtml(loginUrl)}" class="btn">Sign in with Cognito</a>
    </div>

    <div class="card">
      <h2>Configuration</h2>
      <div class="row"><span class="label">Cognito URL</span><span class="value">${escapeHtml(COGNITO_URL)}</span></div>
      <div class="row"><span class="label">Client ID</span><span class="value">${escapeHtml(CLIENT_ID)}</span></div>
      <div class="row"><span class="label">Redirect URI</span><span class="value">${escapeHtml(REDIRECT_URI)}</span></div>
    </div>
  `
    )
  );
}

async function handleCallback(
  url: URL,
  res: http.ServerResponse
): Promise<void> {
  const code = getQueryParam(url, "code");
  const error = getQueryParam(url, "error");

  if (error) {
    const errorDesc = getQueryParam(url, "error_description") || "Unknown error";
    sendHtml(
      res,
      page(
        "Error",
        `
      <h1>Authentication Error</h1>
      <div class="error">${escapeHtml(error)}: ${escapeHtml(errorDesc)}</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
    return;
  }

  if (!code) {
    sendHtml(
      res,
      page(
        "Error",
        `
      <h1>Missing Code</h1>
      <div class="error">No authorization code received.</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
    return;
  }

  // Exchange code for tokens
  const tokenRes = await fetch(`${COGNITO_URL}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    }),
  });

  const tokens = (await tokenRes.json()) as Record<string, unknown>;

  if (!tokenRes.ok) {
    sendHtml(
      res,
      page(
        "Error",
        `
      <h1>Token Exchange Failed</h1>
      <div class="error">${escapeHtml(JSON.stringify(tokens, null, 2))}</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
    return;
  }

  // Decode ID token payload (no verification - just for display)
  const idToken = tokens.id_token as string;
  const payload = JSON.parse(
    Buffer.from(idToken.split(".")[1], "base64url").toString()
  );

  // Fetch user info
  const userInfoRes = await fetch(`${COGNITO_URL}/oauth2/userInfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const userInfo = userInfoRes.ok
    ? ((await userInfoRes.json()) as Record<string, unknown>)
    : null;

  const username = escapeHtml(
    String(payload["cognito:username"] || payload.sub || "")
  );
  const email = escapeHtml(String(payload.email || "-"));
  const sub = escapeHtml(String(payload.sub || ""));
  const iss = escapeHtml(String(payload.iss || ""));
  const iat = new Date((payload.iat as number) * 1000).toLocaleString();
  const exp = new Date((payload.exp as number) * 1000).toLocaleString();
  const emailVerified = payload.email_verified
    ? '<span class="badge badge-green">Yes</span>'
    : '<span class="badge badge-gray">No</span>';

  const accessToken = escapeHtml(String(tokens.access_token || ""));
  const idTokenEscaped = escapeHtml(String(tokens.id_token || ""));
  const refreshToken = escapeHtml(String(tokens.refresh_token || ""));
  const expiresIn = escapeHtml(String(tokens.expires_in || ""));

  const userInfoHtml = userInfo
    ? `
    <div class="card">
      <h2>UserInfo Endpoint</h2>
      ${Object.entries(userInfo)
        .map(
          ([k, v]) =>
            `<div class="row"><span class="label">${escapeHtml(String(k))}</span><span class="value">${escapeHtml(String(v))}</span></div>`
        )
        .join("")}
    </div>
    `
    : "";

  sendHtml(
    res,
    page(
      "Logged In",
      `
    <h1>Authenticated!</h1>
    <p class="subtitle">Successfully signed in via Cognitox</p>

    <div class="card">
      <h2>User Profile</h2>
      <div class="row"><span class="label">Username</span><span class="value">${username}</span></div>
      <div class="row"><span class="label">Email</span><span class="value">${email}</span></div>
      <div class="row"><span class="label">Email Verified</span><span class="value">${emailVerified}</span></div>
      <div class="row"><span class="label">Subject</span><span class="value">${sub}</span></div>
      <div class="row"><span class="label">Issuer</span><span class="value">${iss}</span></div>
      <div class="row"><span class="label">Issued At</span><span class="value">${escapeHtml(iat)}</span></div>
      <div class="row"><span class="label">Expires</span><span class="value">${escapeHtml(exp)}</span></div>
    </div>

    ${userInfoHtml}

    <div class="card">
      <h2>Tokens</h2>
      <p style="font-size: 13px; color: #666; margin-bottom: 12px;">Expires in: ${expiresIn}s</p>

      <div style="margin-bottom: 12px;">
        <strong style="font-size: 13px;">Access Token</strong>
        <div class="token-box">${accessToken}</div>
      </div>
      <div style="margin-bottom: 12px;">
        <strong style="font-size: 13px;">ID Token</strong>
        <div class="token-box">${idTokenEscaped}</div>
      </div>
      <div>
        <strong style="font-size: 13px;">Refresh Token</strong>
        <div class="token-box">${refreshToken}</div>
      </div>
    </div>

    <div class="actions">
      <a href="/" class="btn btn-outline">Home</a>
    </div>
  `
    )
  );
}

async function handleApiMe(
  url: URL,
  req: http.IncomingMessage,
  res: http.ServerResponse
): Promise<void> {
  const token =
    getQueryParam(url, "token") ||
    req.headers["authorization"]?.replace("Bearer ", "");

  if (!token) {
    sendJson(res, { error: "No token provided" }, 401);
    return;
  }

  const cognitoRes = await fetch(`${COGNITO_URL}/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser",
    },
    body: JSON.stringify({ AccessToken: token }),
  });

  if (!cognitoRes.ok) {
    sendJson(res, { error: "Invalid or expired token" }, 401);
    return;
  }

  const user = await cognitoRes.json();
  sendJson(res, user);
}

// -------------------------------------------------------------------
// Server
// -------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://localhost:${PORT}`);
  const pathname = url.pathname;

  try {
    if (req.method === "GET" && pathname === "/") {
      handleHome(res);
    } else if (req.method === "GET" && pathname === "/callback") {
      await handleCallback(url, res);
    } else if (req.method === "GET" && pathname === "/api/me") {
      await handleApiMe(url, req, res);
    } else {
      sendHtml(
        res,
        page("Not Found", `<h1>404</h1><p>Page not found.</p>`),
        404
      );
    }
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Internal Server Error";
    sendHtml(
      res,
      page(
        "Error",
        `<h1>Server Error</h1><div class="error">${escapeHtml(message)}</div>`
      ),
      500
    );
  }
});

console.log(`
  Cognitox Demo App
  =================
  App:      http://localhost:${PORT}
  Cognito:  ${COGNITO_URL}
  Client:   ${CLIENT_ID || "(not set - pass CLIENT_ID env var)"}
`);

server.listen(PORT);

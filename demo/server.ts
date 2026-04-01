import { Hono } from "hono";
import { serve } from "@hono/node-server";

const COGNITO_URL = "http://localhost:9229";
const CLIENT_ID = process.env.CLIENT_ID || "";
const REDIRECT_URI = "http://localhost:3000/callback";
const PORT = 3000;

const app = new Hono();

// -------------------------------------------------------------------
// HTML helpers
// -------------------------------------------------------------------

function page(title: string, body: string) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - Cognitox Demo</title>
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
// Routes
// -------------------------------------------------------------------

// Home - show login button
app.get("/", (c) => {
  if (!CLIENT_ID) {
    return c.html(
      page(
        "Setup Required",
        `
      <h1>Cognitox Demo App</h1>
      <p class="subtitle">A sample app demonstrating OAuth login with Cognitox</p>
      <div class="error">
        <strong>CLIENT_ID not set.</strong><br><br>
        Start with: <code>CLIENT_ID=your_client_id npm run dev</code><br><br>
        You can find the Client ID in the <a href="http://localhost:9229/admin/">Cognitox Admin Console</a>.
      </div>
    `
      )
    );
  }

  const loginUrl = `${COGNITO_URL}/ui/?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid+email+profile`;

  return c.html(
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
      <a href="${loginUrl}" class="btn">Sign in with Cognito</a>
    </div>

    <div class="card">
      <h2>Configuration</h2>
      <div class="row"><span class="label">Cognito URL</span><span class="value">${COGNITO_URL}</span></div>
      <div class="row"><span class="label">Client ID</span><span class="value">${CLIENT_ID}</span></div>
      <div class="row"><span class="label">Redirect URI</span><span class="value">${REDIRECT_URI}</span></div>
    </div>
  `
    )
  );
});

// OAuth callback - exchange code for tokens
app.get("/callback", async (c) => {
  const code = c.req.query("code");
  const error = c.req.query("error");

  if (error) {
    return c.html(
      page(
        "Error",
        `
      <h1>Authentication Error</h1>
      <div class="error">${error}: ${c.req.query("error_description") || "Unknown error"}</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
  }

  if (!code) {
    return c.html(
      page(
        "Error",
        `
      <h1>Missing Code</h1>
      <div class="error">No authorization code received.</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
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
    return c.html(
      page(
        "Error",
        `
      <h1>Token Exchange Failed</h1>
      <div class="error">${JSON.stringify(tokens, null, 2)}</div>
      <a href="/" class="btn btn-outline">Back to Home</a>
    `
      )
    );
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

  return c.html(
    page(
      "Logged In",
      `
    <h1>Authenticated!</h1>
    <p class="subtitle">Successfully signed in via Cognitox</p>

    <div class="card">
      <h2>User Profile</h2>
      <div class="row"><span class="label">Username</span><span class="value">${payload["cognito:username"] || payload.sub}</span></div>
      <div class="row"><span class="label">Email</span><span class="value">${payload.email || "-"}</span></div>
      <div class="row"><span class="label">Email Verified</span><span class="value">${payload.email_verified ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-gray">No</span>'}</span></div>
      <div class="row"><span class="label">Subject</span><span class="value">${payload.sub}</span></div>
      <div class="row"><span class="label">Issuer</span><span class="value">${payload.iss}</span></div>
      <div class="row"><span class="label">Issued At</span><span class="value">${new Date(payload.iat * 1000).toLocaleString()}</span></div>
      <div class="row"><span class="label">Expires</span><span class="value">${new Date(payload.exp * 1000).toLocaleString()}</span></div>
    </div>

    ${
      userInfo
        ? `
    <div class="card">
      <h2>UserInfo Endpoint</h2>
      ${Object.entries(userInfo)
        .map(
          ([k, v]) =>
            `<div class="row"><span class="label">${k}</span><span class="value">${v}</span></div>`
        )
        .join("")}
    </div>
    `
        : ""
    }

    <div class="card">
      <h2>Tokens</h2>
      <p style="font-size: 13px; color: #666; margin-bottom: 12px;">Expires in: ${tokens.expires_in}s</p>

      <div style="margin-bottom: 12px;">
        <strong style="font-size: 13px;">Access Token</strong>
        <div class="token-box">${tokens.access_token}</div>
      </div>
      <div style="margin-bottom: 12px;">
        <strong style="font-size: 13px;">ID Token</strong>
        <div class="token-box">${tokens.id_token}</div>
      </div>
      <div>
        <strong style="font-size: 13px;">Refresh Token</strong>
        <div class="token-box">${tokens.refresh_token}</div>
      </div>
    </div>

    <div class="actions">
      <a href="/" class="btn btn-outline">Home</a>
      <a href="/api/me?token=${tokens.access_token}" class="btn btn-outline">Call /api/me</a>
    </div>
  `
    )
  );
});

// Protected API endpoint example
app.get("/api/me", async (c) => {
  const token =
    c.req.query("token") ||
    c.req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return c.json({ error: "No token provided" }, 401);
  }

  // Call Cognito GetUser to validate the token
  const res = await fetch(`${COGNITO_URL}/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser",
    },
    body: JSON.stringify({ AccessToken: token }),
  });

  if (!res.ok) {
    return c.json({ error: "Invalid or expired token" }, 401);
  }

  const user = await res.json();
  return c.json(user);
});

// -------------------------------------------------------------------
// Start
// -------------------------------------------------------------------

console.log(`
  Cognitox Demo App
  =================
  App:      http://localhost:${PORT}
  Cognito:  ${COGNITO_URL}
  Client:   ${CLIENT_ID || "(not set - pass CLIENT_ID env var)"}
`);

serve({ fetch: app.fetch, port: PORT });

const QUICK_LINKS = [
  {
    title: 'Admin Console',
    path: '/admin/',
    description: 'User pools, users, app clients, and branding management UI.',
  },
  {
    title: 'Hosted UI',
    path: '/login',
    description: 'Built-in sign-in and sign-up pages for local auth flow testing.',
  },
  {
    title: 'Health Check',
    path: '/health',
    description: 'Simple readiness endpoint for containers and local scripts.',
  },
  {
    title: 'OpenID Discovery',
    path: '/.well-known/openid-configuration',
    description: 'OIDC metadata for authorization, token, userinfo, and JWKS endpoints.',
  },
] as const

const ENV_VARS = [
  ['COGNITOX_PORT', '9229', 'Port used by the server and embedded UIs.'],
  ['COGNITOX_STORAGE_MODE', 'memory', 'Use `persistent` to enable file-backed state snapshots.'],
  ['COGNITOX_DATA_FILE', '(unset)', 'Snapshot file path required when persistence mode is enabled.'],
  ['RUST_LOG', 'info', 'Tracing filter. Use `debug` only when you need verbose request logs.'],
] as const

const LIMITATIONS = [
  'SRP authentication (`USER_SRP_AUTH`) is only partially implemented.',
  'Lambda triggers are not supported.',
  'Confirmation codes are returned by the API but are not delivered by email or SMS.',
  'MFA settings are stored, but MFA is not enforced during sign-in flows.',
  'Advanced security and risk evaluation are stored as config only.',
] as const

export function Docs() {
  const origin = typeof window === 'undefined' ? 'http://localhost:9229' : window.location.origin

  const endpoints = [
    { label: 'Base API', url: `${origin}/`, method: 'POST', note: 'Cognito Identity Provider API via `X-Amz-Target`.' },
    { label: 'Hosted UI', url: `${origin}/login`, method: 'GET', note: 'Managed sign-in and sign-up UI.' },
    { label: 'Admin Console', url: `${origin}/admin/`, method: 'GET', note: 'Embedded admin SPA.' },
    { label: 'Health', url: `${origin}/health`, method: 'GET', note: 'Health check endpoint.' },
    { label: 'Authorize', url: `${origin}/oauth2/authorize`, method: 'GET', note: 'OAuth 2.0 authorization endpoint.' },
    { label: 'Token', url: `${origin}/oauth2/token`, method: 'POST', note: 'OAuth 2.0 token endpoint.' },
    { label: 'UserInfo', url: `${origin}/oauth2/userInfo`, method: 'GET', note: 'OIDC user info endpoint.' },
    { label: 'Discovery', url: `${origin}/.well-known/openid-configuration`, method: 'GET', note: 'OIDC discovery metadata.' },
    { label: 'JWKS', url: `${origin}/.well-known/jwks.json`, method: 'GET', note: 'RSA signing keys for token verification.' },
  ]

  const jsExample = `import { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";

const client = new CognitoIdentityProviderClient({
  region: "local",
  endpoint: "${origin}",
  credentials: { accessKeyId: "local", secretAccessKey: "local" },
});`

  const pythonExample = `import boto3

client = boto3.client(
    "cognito-idp",
    region_name="local",
    endpoint_url="${origin}",
    aws_access_key_id="local",
    aws_secret_access_key="local",
)`

  const hostedUiExample = `${origin}/login?response_type=code&client_id=<client-id>&redirect_uri=http://localhost:3000/callback&scope=openid`

  return (
    <div class="max-w-6xl page-enter admin-docs space-y-6">
      <section class="rounded-box border border-base-content/10 bg-base-100 p-6 shadow">
        <div class="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div class="badge badge-outline mb-3">Built-in Docs</div>
            <h1 class="text-3xl font-bold">Cognitox Documentation</h1>
            <p class="mt-2 max-w-3xl text-base-content/70">
              Local Amazon Cognito User Pools emulator with embedded Hosted UI, OAuth/OIDC endpoints,
              and an admin console for day-to-day testing.
            </p>
          </div>
          <div class="rounded-box bg-base-200 px-4 py-3 text-sm">
            <div class="text-base-content/60">Current server origin</div>
            <code class="font-mono text-base">{origin}</code>
          </div>
        </div>
      </section>

      <section class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {QUICK_LINKS.map(link => (
          <a key={link.title} href={link.path} class="card bg-base-100 shadow hover:shadow-md transition-shadow">
            <div class="card-body">
              <div class="text-sm uppercase tracking-[0.2em] text-base-content/45">Quick Link</div>
              <h2 class="card-title">{link.title}</h2>
              <p class="text-sm text-base-content/65">{link.description}</p>
              <code class="mt-2 text-xs text-primary">{link.path}</code>
            </div>
          </a>
        ))}
      </section>

      <section class="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">Useful Endpoints</h2>
            <div class="overflow-x-auto">
              <table class="table table-sm">
                <thead>
                  <tr>
                    <th>Surface</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Purpose</th>
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map(endpoint => (
                    <tr key={endpoint.url}>
                      <td class="font-medium">{endpoint.label}</td>
                      <td><span class="badge badge-ghost">{endpoint.method}</span></td>
                      <td><code class="text-xs">{endpoint.url}</code></td>
                      <td class="text-base-content/65">{endpoint.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">Getting Started</h2>
            <ol class="list-decimal space-y-3 pl-5 text-sm leading-6 text-base-content/80">
              <li>Create a user pool from the admin console.</li>
              <li>Add an app client and set callback URLs for your local app.</li>
              <li>Point your SDK endpoint to the server origin shown above.</li>
              <li>Use the Hosted UI or direct Cognito API calls to exercise your auth flows.</li>
              <li>Turn on persistent storage only when you need state across restarts.</li>
            </ol>
            <div class="divider my-2" />
            <div>
              <div class="mb-2 text-sm font-semibold">Hosted UI Example</div>
              <pre><code>{hostedUiExample}</code></pre>
            </div>
          </div>
        </div>
      </section>

      <section class="grid gap-6 xl:grid-cols-2">
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">SDK Example: JavaScript</h2>
            <pre><code>{jsExample}</code></pre>
          </div>
        </div>

        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">SDK Example: Python</h2>
            <pre><code>{pythonExample}</code></pre>
          </div>
        </div>
      </section>

      <section class="grid gap-6 xl:grid-cols-[1fr_0.9fr]">
        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">Configuration</h2>
            <div class="overflow-x-auto">
              <table class="table table-sm">
                <thead>
                  <tr>
                    <th>Variable</th>
                    <th>Default</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {ENV_VARS.map(([name, value, description]) => (
                    <tr key={name}>
                      <td><code>{name}</code></td>
                      <td><code>{value}</code></td>
                      <td class="text-base-content/65">{description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="card bg-base-100 shadow">
          <div class="card-body">
            <h2 class="card-title">Known Limitations</h2>
            <ul class="space-y-3 text-sm leading-6 text-base-content/80">
              {LIMITATIONS.map(item => (
                <li key={item} class="flex gap-3">
                  <span class="mt-2 inline-block h-2 w-2 shrink-0 rounded-full bg-warning" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>
    </div>
  )
}

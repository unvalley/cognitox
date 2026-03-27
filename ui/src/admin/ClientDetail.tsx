import { useState, useEffect } from 'preact/hooks'
import type { AdminPage, UserPool, UserPoolClient } from '../lib/types'
import { describeUserPoolClient, deleteUserPoolClient } from '../lib/api'

interface Props {
  userPool: UserPool
  client: UserPoolClient
  navigate: (page: AdminPage, context?: { userPool?: UserPool; client?: UserPoolClient }) => void
}

export function ClientDetail({ userPool, client: initialClient, navigate }: Props) {
  const [client, setClient] = useState<UserPoolClient | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    describeUserPoolClient(userPool.Id, initialClient.ClientId)
      .then(c => setClient(c))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load client'))
      .finally(() => setLoading(false))
  }, [userPool.Id, initialClient.ClientId])

  async function handleDelete() {
    if (!client) return
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return
    try {
      await deleteUserPoolClient(userPool.Id, client.ClientId)
      navigate('clients', { userPool })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete client')
    }
  }

  async function copyClientId() {
    if (!client) return
    await navigator.clipboard.writeText(client.ClientId)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function getHostedUIUrl(): string {
    if (!client) return ''
    const callbackUrl = client.CallbackURLs?.[0] || 'http://localhost:3000/callback'
    return `http://localhost:9229/ui/?response_type=code&client_id=${client.ClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
  }

  function renderTags(items: string[] | undefined, label: string) {
    if (!items || items.length === 0) return <span class="text-base-content/40 text-sm">None configured</span>
    return <div class="flex flex-wrap gap-2">{items.map(item => <span key={item} class="badge badge-info badge-outline badge-sm">{item}</span>)}</div>
  }

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('user-pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate('user-pool-detail', { userPool })}>{userPool.Name}</button></li>
            <li><button class="link link-primary" onClick={() => navigate('clients', { userPool })}>App Clients</button></li>
            <li>{initialClient.ClientName}</li>
          </ul>
        </div>
        <div class="flex justify-between items-center flex-wrap gap-4">
          <h1 class="text-3xl font-bold">{initialClient.ClientName}</h1>
          <button class="btn btn-error btn-outline btn-sm" onClick={handleDelete}>Delete Client</button>
        </div>
      </div>

      {error && <div class="alert alert-error mb-6">{error}</div>}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : client && (
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Client Information</h2>
              <table class="table table-sm">
                <tbody>
                  <tr><td class="font-medium text-base-content/60 w-40">Client Name</td><td>{client.ClientName}</td></tr>
                  <tr>
                    <td class="font-medium text-base-content/60">Client ID</td>
                    <td>
                      <div class="flex items-center gap-2">
                        <code class="text-sm break-all">{client.ClientId}</code>
                        <button class="btn btn-ghost btn-xs" onClick={copyClientId}>{copied ? 'Copied!' : 'Copy'}</button>
                      </div>
                    </td>
                  </tr>
                  <tr><td class="font-medium text-base-content/60">User Pool ID</td><td><code class="text-sm">{client.UserPoolId}</code></td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">OAuth 2.0 Settings</h2>
              <table class="table table-sm">
                <tbody>
                  <tr><td class="font-medium text-base-content/60 w-40">OAuth Flows</td><td>{renderTags(client.AllowedOAuthFlows, 'flows')}</td></tr>
                  <tr><td class="font-medium text-base-content/60">OAuth Scopes</td><td>{renderTags(client.AllowedOAuthScopes, 'scopes')}</td></tr>
                  <tr><td class="font-medium text-base-content/60">Auth Flows</td><td>{renderTags(client.ExplicitAuthFlows, 'auth flows')}</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Callback URLs</h2>
              {client.CallbackURLs && client.CallbackURLs.length > 0 ? (
                <ul class="space-y-2">{client.CallbackURLs.map(url => <li key={url}><code class="text-sm break-all">{url}</code></li>)}</ul>
              ) : (
                <p class="text-base-content/40 text-sm">No callback URLs configured</p>
              )}
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Logout URLs</h2>
              {client.LogoutURLs && client.LogoutURLs.length > 0 ? (
                <ul class="space-y-2">{client.LogoutURLs.map(url => <li key={url}><code class="text-sm break-all">{url}</code></li>)}</ul>
              ) : (
                <p class="text-base-content/40 text-sm">No logout URLs configured</p>
              )}
            </div>
          </div>

          <div class="card bg-base-100 shadow lg:col-span-2">
            <div class="card-body">
              <h2 class="card-title">Test Hosted UI</h2>
              <p class="text-base-content/60 text-sm">Use this URL to test the hosted login UI:</p>
              <div class="bg-base-200 p-4 rounded-lg flex items-center gap-4 flex-wrap">
                <code class="flex-1 min-w-0 text-sm break-all">{getHostedUIUrl()}</code>
                <a href={getHostedUIUrl()} target="_blank" rel="noopener" class="btn btn-primary btn-sm">Open Hosted UI</a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

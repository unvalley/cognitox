import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { describeUserPoolClient, deleteUserPoolClient, updateUserPoolClient } from '../lib/api'

interface Props {
  userPool: UserPool
  client: UserPoolClient
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

const OAUTH_FLOW_OPTIONS = ['code', 'implicit', 'client_credentials']
const OAUTH_SCOPE_OPTIONS = ['openid', 'email', 'phone', 'profile', 'aws.cognito.signin.user.admin']

export function ClientDetail({ userPool, client: initialClient, navigate }: Props) {
  const [client, setClient] = useState<UserPoolClient | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [editing, setEditing] = useState(false)

  // Editable fields
  const [callbackUrls, setCallbackUrls] = useState('')
  const [logoutUrls, setLogoutUrls] = useState('')
  const [selectedFlows, setSelectedFlows] = useState<string[]>([])
  const [selectedScopes, setSelectedScopes] = useState<string[]>([])

  useEffect(() => {
    describeUserPoolClient(userPool.Id, initialClient.ClientId)
      .then(c => {
        setClient(c)
        syncEditState(c)
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load client'))
      .finally(() => setLoading(false))
  }, [userPool.Id, initialClient.ClientId])

  function syncEditState(c: UserPoolClient) {
    setCallbackUrls(c.CallbackURLs?.join('\n') || '')
    setLogoutUrls(c.LogoutURLs?.join('\n') || '')
    setSelectedFlows(c.AllowedOAuthFlows || [])
    setSelectedScopes(c.AllowedOAuthScopes || [])
  }

  function startEditing() {
    if (client) syncEditState(client)
    setEditing(true)
  }

  function cancelEditing() {
    if (client) syncEditState(client)
    setEditing(false)
  }

  async function handleSave() {
    if (!client) return
    try {
      setSaving(true)
      setError(null)
      const parsedCallbackUrls = callbackUrls.split('\n').map(u => u.trim()).filter(Boolean)
      const parsedLogoutUrls = logoutUrls.split('\n').map(u => u.trim()).filter(Boolean)
      const hasOAuth = parsedCallbackUrls.length > 0 || selectedFlows.length > 0 || selectedScopes.length > 0

      const updated = await updateUserPoolClient(userPool.Id, client.ClientId, {
        ClientName: client.ClientName,
        CallbackURLs: parsedCallbackUrls,
        LogoutURLs: parsedLogoutUrls,
        AllowedOAuthFlows: selectedFlows,
        AllowedOAuthScopes: selectedScopes,
        AllowedOAuthFlowsUserPoolClient: hasOAuth,
      })
      setClient(updated)
      syncEditState(updated)
      setEditing(false)
      setSuccess('Client updated')
      setTimeout(() => setSuccess(null), 3000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update client')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete() {
    if (!client) return
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return
    try {
      await deleteUserPoolClient(userPool.Id, client.ClientId)
      navigate(`/admin/pools/${userPool.Id}/clients`)
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

  function toggleFlow(flow: string) {
    setSelectedFlows(prev => prev.includes(flow) ? prev.filter(f => f !== flow) : [...prev, flow])
  }

  function toggleScope(scope: string) {
    setSelectedScopes(prev => prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope])
  }

  function getHostedUIUrl(): string {
    if (!client) return ''
    const cbUrls = client.CallbackURLs || []
    const callbackUrl = cbUrls[0] || 'http://localhost:3000/callback'
    return `http://localhost:9229/ui/?response_type=code&client_id=${client.ClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
  }

  function renderTags(items: string[] | undefined) {
    if (!items || items.length === 0) return <span class="text-base-content/40 text-sm">None configured</span>
    return <div class="flex flex-wrap gap-2">{items.map(item => <span key={item} class="badge badge-info badge-outline badge-sm">{item}</span>)}</div>
  }

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}`)}>{userPool.Name}</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients`)}>App Clients</button></li>
            <li>{initialClient.ClientName}</li>
          </ul>
        </div>
        <div class="flex justify-between items-center flex-wrap gap-4">
          <h1 class="text-3xl font-bold">{initialClient.ClientName}</h1>
          <div class="flex gap-3">
            {editing ? (
              <>
                <button class="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
                  {saving ? <><span class="loading loading-spinner loading-sm"></span> Saving...</> : 'Save'}
                </button>
                <button class="btn btn-ghost btn-sm" onClick={cancelEditing}>Cancel</button>
              </>
            ) : (
              <button class="btn btn-outline btn-sm" onClick={startEditing}>Edit</button>
            )}
            <button class="btn btn-error btn-outline btn-sm" onClick={handleDelete}>Delete</button>
          </div>
        </div>
      </div>

      {error && (
        <div class="alert alert-error mb-6">
          <span>{error}</span>
          <button class="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}
      {success && <div class="alert alert-success mb-6">{success}</div>}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : client && (
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Client Information - always read only */}
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

          {/* OAuth Flows */}
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">OAuth 2.0 Flows</h2>
              {editing ? (
                <div class="space-y-3 mt-2">
                  {OAUTH_FLOW_OPTIONS.map(flow => (
                    <label key={flow} class="flex items-center gap-3 cursor-pointer">
                      <input type="checkbox" class="checkbox checkbox-sm checkbox-primary" checked={selectedFlows.includes(flow)} onChange={() => toggleFlow(flow)} />
                      <span class="label-text">{flow}</span>
                    </label>
                  ))}
                </div>
              ) : (
                <div class="mt-2">{renderTags(client.AllowedOAuthFlows)}</div>
              )}
            </div>
          </div>

          {/* OAuth Scopes */}
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">OAuth 2.0 Scopes</h2>
              {editing ? (
                <div class="space-y-3 mt-2">
                  {OAUTH_SCOPE_OPTIONS.map(scope => (
                    <label key={scope} class="flex items-center gap-3 cursor-pointer">
                      <input type="checkbox" class="checkbox checkbox-sm checkbox-primary" checked={selectedScopes.includes(scope)} onChange={() => toggleScope(scope)} />
                      <span class="label-text font-mono text-sm">{scope}</span>
                    </label>
                  ))}
                </div>
              ) : (
                <div class="mt-2">{renderTags(client.AllowedOAuthScopes)}</div>
              )}
            </div>
          </div>

          {/* Callback URLs */}
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Callback URLs</h2>
              {editing ? (
                <div class="form-control mt-2">
                  <label class="label pb-1.5"><span class="label-text text-base-content/60">One URL per line</span></label>
                  <textarea class="textarea textarea-bordered w-full font-mono text-sm" rows={4} placeholder="http://localhost:3000/callback" value={callbackUrls} onInput={e => setCallbackUrls((e.target as HTMLTextAreaElement).value)} />
                </div>
              ) : client.CallbackURLs && client.CallbackURLs.length > 0 ? (
                <ul class="space-y-2 mt-2">{client.CallbackURLs.map(url => <li key={url}><code class="text-sm break-all">{url}</code></li>)}</ul>
              ) : (
                <p class="text-base-content/40 text-sm mt-2">None configured</p>
              )}
            </div>
          </div>

          {/* Logout URLs */}
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Logout URLs</h2>
              {editing ? (
                <div class="form-control mt-2">
                  <label class="label pb-1.5"><span class="label-text text-base-content/60">One URL per line</span></label>
                  <textarea class="textarea textarea-bordered w-full font-mono text-sm" rows={4} placeholder="http://localhost:3000/logout" value={logoutUrls} onInput={e => setLogoutUrls((e.target as HTMLTextAreaElement).value)} />
                </div>
              ) : client.LogoutURLs && client.LogoutURLs.length > 0 ? (
                <ul class="space-y-2 mt-2">{client.LogoutURLs.map(url => <li key={url}><code class="text-sm break-all">{url}</code></li>)}</ul>
              ) : (
                <p class="text-base-content/40 text-sm mt-2">None configured</p>
              )}
            </div>
          </div>

          {/* Test Hosted UI */}
          <div class="card bg-base-100 shadow lg:col-span-2">
            <div class="card-body">
              <h2 class="card-title">Test Hosted UI</h2>
              <p class="text-base-content/60 text-sm">Use this URL to test the hosted login UI:</p>
              <div class="bg-base-200 p-4 rounded-lg flex items-center gap-4 flex-wrap mt-2">
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

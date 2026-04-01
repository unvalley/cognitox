import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { listUserPoolClients, createUserPoolClient, deleteUserPoolClient } from '../lib/api'

interface Props {
  userPool: UserPool
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function ClientList({ userPool, navigate }: Props) {
  const [clients, setClients] = useState<UserPoolClient[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newClientName, setNewClientName] = useState('')
  const [newCallbackUrls, setNewCallbackUrls] = useState('')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    listUserPoolClients(userPool.Id)
      .then(c => setClients(c))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load clients'))
      .finally(() => setLoading(false))
  }, [userPool.Id])

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newClientName.trim()) return
    try {
      setCreating(true)
      const callbackUrls = newCallbackUrls.split('\n').map(url => url.trim()).filter(url => url.length > 0)
      const client = await createUserPoolClient(
        userPool.Id, newClientName.trim(),
        callbackUrls.length > 0 ? callbackUrls : undefined,
        ['code'], ['openid', 'email', 'profile']
      )
      setClients(prev => [...prev, client])
      setShowCreateModal(false)
      setNewClientName('')
      setNewCallbackUrls('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create client')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(client: UserPoolClient) {
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return
    try {
      await deleteUserPoolClient(userPool.Id, client.ClientId)
      setClients(prev => prev.filter(c => c.ClientId !== client.ClientId))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete client')
    }
  }

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}`)}>{userPool.Name}</button></li>
            <li>App Clients</li>
          </ul>
        </div>
        <div class="flex justify-between items-center">
          <h1 class="text-3xl font-bold">App Clients</h1>
          <button class="btn btn-primary" onClick={() => setShowCreateModal(true)}>Create Client</button>
        </div>
      </div>

      {error && (
        <div class="alert alert-error mb-6">
          <span>{error}</span>
          <button class="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : clients.length === 0 ? (
        <div class="card bg-base-100 shadow">
          <div class="card-body items-center text-center py-16">
            <h2 class="card-title">No App Clients</h2>
            <p class="text-base-content/60">Create your first app client for this pool.</p>
            <button class="btn btn-primary mt-4" onClick={() => setShowCreateModal(true)}>Create Client</button>
          </div>
        </div>
      ) : (
        <div class="card bg-base-100 shadow">
          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Client ID</th>
                  <th>OAuth Flows</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {clients.map(client => (
                  <tr key={client.ClientId}>
                    <td>
                      <button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients/${client.ClientId}`, { client })}>{client.ClientName}</button>
                    </td>
                    <td><code class="badge badge-ghost text-xs">{client.ClientId}</code></td>
                    <td>{client.AllowedOAuthFlows?.join(', ') || '-'}</td>
                    <td>
                      <div class="flex gap-2">
                        <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients/${client.ClientId}`, { client })}>View</button>
                        <button class="btn btn-error btn-ghost btn-sm" onClick={() => handleDelete(client)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {showCreateModal && (
        <dialog class="modal modal-open">
          <div class="modal-box">
            <h3 class="font-bold text-lg mb-4">Create App Client</h3>
            <form onSubmit={handleCreate}>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Client Name</span></label>
                <input type="text" class="input input-bordered" placeholder="my-web-app" value={newClientName} onInput={e => setNewClientName((e.target as HTMLInputElement).value)} disabled={creating} required />
              </div>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Callback URLs (one per line)</span></label>
                <textarea class="textarea textarea-bordered" placeholder="http://localhost:3000/callback" value={newCallbackUrls} onInput={e => setNewCallbackUrls((e.target as HTMLTextAreaElement).value)} disabled={creating} rows={3} />
              </div>
              <div class="modal-action">
                <button type="button" class="btn" onClick={() => setShowCreateModal(false)} disabled={creating}>Cancel</button>
                <button type="submit" class="btn btn-primary" disabled={creating}>
                  {creating ? <><span class="loading loading-spinner loading-sm"></span> Creating...</> : 'Create'}
                </button>
              </div>
            </form>
          </div>
          <form method="dialog" class="modal-backdrop"><button onClick={() => setShowCreateModal(false)}>close</button></form>
        </dialog>
      )}
    </div>
  )
}

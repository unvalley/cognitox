import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { formatDate } from '../lib/types'
import { describeUserPool, listUsers, listUserPoolClients } from '../lib/api'

interface Props {
  userPool: UserPool
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function UserPoolDetail({ userPool, navigate }: Props) {
  const [pool, setPool] = useState<UserPool | null>(null)
  const [users, setUsers] = useState<User[]>([])
  const [clients, setClients] = useState<UserPoolClient[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([
      describeUserPool(userPool.Id),
      listUsers(userPool.Id),
      listUserPoolClients(userPool.Id),
    ])
      .then(([poolData, usersData, clientsData]) => {
        setPool(poolData)
        setUsers(usersData)
        setClients(clientsData)
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load user pool details'))
      .finally(() => setLoading(false))
  }, [userPool.Id])

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li>{userPool.Name}</li>
          </ul>
        </div>
        <h1 class="text-3xl font-bold">{userPool.Name}</h1>
        <p><code class="badge badge-ghost">{userPool.Id}</code></p>
      </div>

      {error && <div class="alert alert-error mb-6">{error}</div>}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : pool && (
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Pool Information</h2>
              <div class="overflow-x-auto">
                <table class="table table-sm">
                  <tbody>
                    <tr><td class="font-medium text-base-content/60 w-36">Pool ID</td><td><code class="text-sm">{pool.Id}</code></td></tr>
                    <tr><td class="font-medium text-base-content/60">Name</td><td>{pool.Name}</td></tr>
                    <tr><td class="font-medium text-base-content/60">Created</td><td>{formatDate(pool.CreationDate)}</td></tr>
                    <tr><td class="font-medium text-base-content/60">Last Modified</td><td>{formatDate(pool.LastModifiedDate)}</td></tr>
                    {pool.Domain && <tr><td class="font-medium text-base-content/60">Domain</td><td>{pool.Domain}</td></tr>}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex justify-between items-center">
                <h2 class="card-title">Users ({users.length})</h2>
                <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/users`)}>Manage</button>
              </div>
              {users.length === 0 ? (
                <p class="text-base-content/60 text-sm">No users yet</p>
              ) : (
                <ul class="space-y-2">
                  {users.slice(0, 5).map(user => (
                    <li key={user.Username} class="flex justify-between items-center py-2 border-b border-base-200 last:border-0">
                      <button class="link link-primary text-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/users/${user.Username}`, { user })}>{user.Username}</button>
                      <span class={`badge badge-sm ${user.UserStatus === 'CONFIRMED' ? 'badge-success' : 'badge-ghost'}`}>{user.UserStatus}</span>
                    </li>
                  ))}
                </ul>
              )}
              {users.length > 5 && (
                <button class="btn btn-link btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/users`)}>View all {users.length} users</button>
              )}
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex justify-between items-center">
                <h2 class="card-title">App Clients ({clients.length})</h2>
                <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients`)}>Manage</button>
              </div>
              {clients.length === 0 ? (
                <p class="text-base-content/60 text-sm">No app clients yet</p>
              ) : (
                <ul class="space-y-2">
                  {clients.slice(0, 5).map(client => (
                    <li key={client.ClientId} class="flex justify-between items-center py-2 border-b border-base-200 last:border-0">
                      <button class="link link-primary text-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients/${client.ClientId}`, { client })}>{client.ClientName}</button>
                      <code class="badge badge-ghost text-xs">{client.ClientId}</code>
                    </li>
                  ))}
                </ul>
              )}
              {clients.length > 5 && (
                <button class="btn btn-link btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients`)}>View all {clients.length} clients</button>
              )}
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex justify-between items-center">
                <h2 class="card-title">Branding</h2>
                <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/branding`)}>Configure</button>
              </div>
              <p class="text-base-content/60 text-sm">Customize the hosted UI appearance</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { formatDateShort } from '../lib/types'
import { listUserPools, listUsers, listUserPoolClients } from '../lib/api'

interface Props {
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function Dashboard({ navigate }: Props) {
  const [userPools, setUserPools] = useState<UserPool[]>([])
  const [totalUsers, setTotalUsers] = useState(0)
  const [totalClients, setTotalClients] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listUserPools()
      .then(async pools => {
        setUserPools(pools)
        // Fetch counts for all pools in parallel
        const counts = await Promise.all(
          pools.map(async pool => {
            const [users, clients] = await Promise.all([
              listUsers(pool.Id).catch(() => []),
              listUserPoolClients(pool.Id).catch(() => []),
            ])
            return { users: users.length, clients: clients.length }
          })
        )
        setTotalUsers(counts.reduce((sum, c) => sum + c.users, 0))
        setTotalClients(counts.reduce((sum, c) => sum + c.clients, 0))
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load data'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <h1 class="text-3xl font-bold">Dashboard</h1>
        <p class="text-base-content/60">Overview of your Cognito emulator</p>
      </div>

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : error ? (
        <div class="alert alert-error mb-6">{error}</div>
      ) : (
        <>
          <div class="stats shadow mb-8 w-full">
            <div class="stat">
              <div class="stat-title">User Pools</div>
              <div class="stat-value text-primary">{userPools.length}</div>
            </div>
            <div class="stat">
              <div class="stat-title">Total Users</div>
              <div class="stat-value text-primary">{totalUsers}</div>
            </div>
            <div class="stat">
              <div class="stat-title">App Clients</div>
              <div class="stat-value text-primary">{totalClients}</div>
            </div>
          </div>

          <div class="card bg-base-100 shadow mb-6">
            <div class="card-body">
              <h2 class="card-title">User Pools</h2>
              {userPools.length === 0 ? (
                <div class="text-center py-8 text-base-content/60">
                  <p class="mb-4">No user pools yet.</p>
                  <button class="btn btn-primary" onClick={() => navigate('/admin/pools')}>Create User Pool</button>
                </div>
              ) : (
                <>
                  <div class="overflow-x-auto">
                    <table class="table">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>ID</th>
                          <th>Created</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {userPools.slice(0, 5).map(pool => (
                          <tr key={pool.Id}>
                            <td>{pool.Name}</td>
                            <td><code class="badge badge-ghost text-xs">{pool.Id}</code></td>
                            <td>{formatDateShort(pool.CreationDate)}</td>
                            <td>
                              <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${pool.Id}`, { userPool: pool })}>View</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {userPools.length > 5 && (
                    <button class="btn btn-link" onClick={() => navigate('/admin/pools')}>View all {userPools.length} user pools</button>
                  )}
                </>
              )}
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 class="card-title">Need setup details?</h2>
                <p class="text-sm text-base-content/65">
                  Open the built-in docs for endpoint URLs, SDK examples, environment variables, and current limitations.
                </p>
              </div>
              <div class="card-actions">
                <button class="btn btn-outline" onClick={() => navigate('/admin/docs')}>Open Docs</button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

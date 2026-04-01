import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { formatDate } from '../lib/types'
import { listUserPools, createUserPool, deleteUserPool } from '../lib/api'

interface Props {
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function UserPoolList({ navigate }: Props) {
  const [userPools, setUserPools] = useState<UserPool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newPoolName, setNewPoolName] = useState('')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    listUserPools()
      .then(pools => setUserPools(pools))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load user pools'))
      .finally(() => setLoading(false))
  }, [])

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newPoolName.trim()) return
    try {
      setCreating(true)
      const pool = await createUserPool(newPoolName.trim())
      setUserPools(prev => [...prev, pool])
      setShowCreateModal(false)
      setNewPoolName('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create user pool')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(pool: UserPool) {
    if (!confirm(`Are you sure you want to delete "${pool.Name}"?`)) return
    try {
      await deleteUserPool(pool.Id)
      setUserPools(prev => prev.filter(p => p.Id !== pool.Id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete user pool')
    }
  }

  return (
    <div class="max-w-6xl">
      <div class="flex justify-between items-center mb-8">
        <div>
          <h1 class="text-3xl font-bold">User Pools</h1>
          <p class="text-base-content/60">Manage your Cognito user pools</p>
        </div>
        <button class="btn btn-primary" onClick={() => setShowCreateModal(true)}>Create User Pool</button>
      </div>

      {error && (
        <div class="alert alert-error mb-6">
          <span>{error}</span>
          <button class="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : userPools.length === 0 ? (
        <div class="card bg-base-100 shadow">
          <div class="card-body items-center text-center py-16">
            <h2 class="card-title">No User Pools</h2>
            <p class="text-base-content/60">Create your first user pool to get started.</p>
            <button class="btn btn-primary mt-4" onClick={() => setShowCreateModal(true)}>Create User Pool</button>
          </div>
        </div>
      ) : (
        <div class="card bg-base-100 shadow">
          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Pool ID</th>
                  <th>Created</th>
                  <th>Modified</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {userPools.map(pool => (
                  <tr key={pool.Id}>
                    <td>
                      <button class="link link-primary" onClick={() => navigate(`/admin/pools/${pool.Id}`, { userPool: pool })}>{pool.Name}</button>
                    </td>
                    <td><code class="badge badge-ghost text-xs">{pool.Id}</code></td>
                    <td>{formatDate(pool.CreationDate)}</td>
                    <td>{formatDate(pool.LastModifiedDate)}</td>
                    <td>
                      <div class="flex gap-2">
                        <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${pool.Id}`, { userPool: pool })}>View</button>
                        <button class="btn btn-error btn-ghost btn-sm" onClick={() => handleDelete(pool)}>Delete</button>
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
            <h3 class="font-bold text-lg mb-4">Create User Pool</h3>
            <form onSubmit={handleCreate}>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Pool Name</span></label>
                <input
                  type="text"
                  class="input input-bordered"
                  placeholder="my-user-pool"
                  value={newPoolName}
                  onInput={e => setNewPoolName((e.target as HTMLInputElement).value)}
                  disabled={creating}
                  required
                />
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

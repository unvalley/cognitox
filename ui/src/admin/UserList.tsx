import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { formatDate } from '../lib/types'
import { listUsers, adminCreateUser, adminDeleteUser, adminEnableUser, adminDisableUser } from '../lib/api'

interface Props {
  userPool: UserPool
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function UserList({ userPool, navigate }: Props) {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [creating, setCreating] = useState(false)

  useEffect(() => {
    listUsers(userPool.Id)
      .then(u => setUsers(u))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load users'))
      .finally(() => setLoading(false))
  }, [userPool.Id])

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newUsername.trim() || !newEmail.trim()) return
    try {
      setCreating(true)
      const user = await adminCreateUser(userPool.Id, newUsername.trim(), newEmail.trim(), newPassword || undefined)
      setUsers(prev => [...prev, user])
      setShowCreateModal(false)
      setNewUsername('')
      setNewEmail('')
      setNewPassword('')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(user: User) {
    if (!confirm(`Are you sure you want to delete "${user.Username}"?`)) return
    try {
      await adminDeleteUser(userPool.Id, user.Username)
      setUsers(prev => prev.filter(u => u.Username !== user.Username))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete user')
    }
  }

  async function handleToggleEnabled(user: User) {
    try {
      if (user.Enabled) {
        await adminDisableUser(userPool.Id, user.Username)
      } else {
        await adminEnableUser(userPool.Id, user.Username)
      }
      setUsers(prev => prev.map(u => u.Username === user.Username ? { ...u, Enabled: !u.Enabled } : u))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update user')
    }
  }

  function getEmail(user: User): string {
    return user.Attributes?.find(a => a.Name === 'email')?.Value || '-'
  }

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}`)}>{userPool.Name}</button></li>
            <li>Users</li>
          </ul>
        </div>
        <div class="flex justify-between items-center">
          <h1 class="text-3xl font-bold">Users</h1>
          <button class="btn btn-primary" onClick={() => setShowCreateModal(true)}>Create User</button>
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
      ) : users.length === 0 ? (
        <div class="card bg-base-100 shadow">
          <div class="card-body items-center text-center py-16">
            <h2 class="card-title">No Users</h2>
            <p class="text-base-content/60">Create your first user in this pool.</p>
            <button class="btn btn-primary mt-4" onClick={() => setShowCreateModal(true)}>Create User</button>
          </div>
        </div>
      ) : (
        <div class="card bg-base-100 shadow">
          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Status</th>
                  <th>Enabled</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(user => (
                  <tr key={user.Username}>
                    <td>
                      <button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}/users/${user.Username}`, { user })}>{user.Username}</button>
                    </td>
                    <td>{getEmail(user)}</td>
                    <td>
                      <span class={`badge badge-sm ${user.UserStatus === 'CONFIRMED' ? 'badge-success' : 'badge-ghost'}`}>{user.UserStatus}</span>
                    </td>
                    <td>
                      <input
                        type="checkbox"
                        class="toggle toggle-sm toggle-success"
                        checked={user.Enabled}
                        onChange={() => handleToggleEnabled(user)}
                      />
                    </td>
                    <td>{formatDate(user.UserCreateDate)}</td>
                    <td>
                      <div class="flex gap-2">
                        <button class="btn btn-ghost btn-sm" onClick={() => navigate(`/admin/pools/${userPool.Id}/users/${user.Username}`, { user })}>View</button>
                        <button class="btn btn-error btn-ghost btn-sm" onClick={() => handleDelete(user)}>Delete</button>
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
            <h3 class="font-bold text-lg mb-4">Create User</h3>
            <form onSubmit={handleCreate}>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Username</span></label>
                <input type="text" class="input input-bordered" placeholder="johndoe" value={newUsername} onInput={e => setNewUsername((e.target as HTMLInputElement).value)} disabled={creating} required />
              </div>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Email</span></label>
                <input type="email" class="input input-bordered" placeholder="john@example.com" value={newEmail} onInput={e => setNewEmail((e.target as HTMLInputElement).value)} disabled={creating} required />
              </div>
              <div class="form-control mb-4">
                <label class="label"><span class="label-text">Temporary Password (optional)</span></label>
                <input type="password" class="input input-bordered" placeholder="Leave empty to auto-generate" value={newPassword} onInput={e => setNewPassword((e.target as HTMLInputElement).value)} disabled={creating} />
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

import { useState, useEffect } from 'preact/hooks'
import type { AdminPage, UserPool, User } from '../lib/types'
import { adminGetUser, adminDeleteUser, adminEnableUser, adminDisableUser } from '../lib/api'

interface Props {
  userPool: UserPool
  user: User
  navigate: (page: AdminPage, context?: { userPool?: UserPool; user?: User }) => void
}

export function UserDetail({ userPool, user: initialUser, navigate }: Props) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    adminGetUser(userPool.Id, initialUser.Username)
      .then(u => setUser(u))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load user'))
      .finally(() => setLoading(false))
  }, [userPool.Id, initialUser.Username])

  async function handleDelete() {
    if (!user) return
    if (!confirm(`Are you sure you want to delete "${user.Username}"?`)) return
    try {
      await adminDeleteUser(userPool.Id, user.Username)
      navigate('users', { userPool })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete user')
    }
  }

  async function handleToggleEnabled() {
    if (!user) return
    try {
      if (user.Enabled) {
        await adminDisableUser(userPool.Id, user.Username)
      } else {
        await adminEnableUser(userPool.Id, user.Username)
      }
      setUser({ ...user, Enabled: !user.Enabled })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update user')
    }
  }

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('user-pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate('user-pool-detail', { userPool })}>{userPool.Name}</button></li>
            <li><button class="link link-primary" onClick={() => navigate('users', { userPool })}>Users</button></li>
            <li>{initialUser.Username}</li>
          </ul>
        </div>
        <div class="flex justify-between items-center flex-wrap gap-4">
          <h1 class="text-3xl font-bold">{initialUser.Username}</h1>
          <div class="flex gap-3">
            <button class="btn btn-outline btn-sm" onClick={handleToggleEnabled}>
              {user?.Enabled ? 'Disable User' : 'Enable User'}
            </button>
            <button class="btn btn-error btn-outline btn-sm" onClick={handleDelete}>Delete User</button>
          </div>
        </div>
      </div>

      {error && <div class="alert alert-error mb-6">{error}</div>}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : user && (
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">User Information</h2>
              <table class="table table-sm">
                <tbody>
                  <tr><td class="font-medium text-base-content/60 w-36">Username</td><td>{user.Username}</td></tr>
                  <tr>
                    <td class="font-medium text-base-content/60">Status</td>
                    <td><span class={`badge badge-sm ${user.UserStatus === 'CONFIRMED' ? 'badge-success' : 'badge-ghost'}`}>{user.UserStatus}</span></td>
                  </tr>
                  <tr>
                    <td class="font-medium text-base-content/60">Enabled</td>
                    <td><span class={`badge badge-sm ${user.Enabled ? 'badge-success' : 'badge-ghost'}`}>{user.Enabled ? 'Yes' : 'No'}</span></td>
                  </tr>
                  <tr><td class="font-medium text-base-content/60">Created</td><td>{new Date(user.UserCreateDate).toLocaleString()}</td></tr>
                  <tr><td class="font-medium text-base-content/60">Last Modified</td><td>{new Date(user.UserLastModifiedDate).toLocaleString()}</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="card-title">Attributes</h2>
              {user.Attributes && user.Attributes.length > 0 ? (
                <table class="table table-sm">
                  <tbody>
                    {user.Attributes.map(attr => (
                      <tr key={attr.Name}><td class="font-medium text-base-content/60 w-36">{attr.Name}</td><td class="break-all">{attr.Value}</td></tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p class="text-base-content/60 text-sm">No attributes</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

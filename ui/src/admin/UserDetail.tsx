import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient, UserAttribute } from '../lib/types'
import { formatDate } from '../lib/types'
import {
  adminGetUser, adminDeleteUser, adminEnableUser, adminDisableUser,
  adminUpdateUserAttributes, adminSetUserPassword, adminConfirmSignUp,
} from '../lib/api'

interface Props {
  userPool: UserPool
  user: User
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function UserDetail({ userPool, user: initialUser, navigate }: Props) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [editing, setEditing] = useState(false)

  // Editable attributes
  const [editAttrs, setEditAttrs] = useState<UserAttribute[]>([])
  const [newAttrName, setNewAttrName] = useState('')
  const [newAttrValue, setNewAttrValue] = useState('')

  // Password reset
  const [showPasswordForm, setShowPasswordForm] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [passwordPermanent, setPasswordPermanent] = useState(true)

  useEffect(() => {
    adminGetUser(userPool.Id, initialUser.Username)
      .then(u => {
        setUser(u)
        setEditAttrs(u.Attributes || u.UserAttributes || [])
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load user'))
      .finally(() => setLoading(false))
  }, [userPool.Id, initialUser.Username])

  function startEditing() {
    if (!user) return
    setEditAttrs(user.Attributes || user.UserAttributes || [])
    setEditing(true)
  }

  function cancelEditing() {
    if (!user) return
    setEditAttrs(user.Attributes || user.UserAttributes || [])
    setNewAttrName('')
    setNewAttrValue('')
    setEditing(false)
  }

  async function handleSaveAttributes() {
    if (!user) return
    try {
      setSaving(true)
      setError(null)
      await adminUpdateUserAttributes(userPool.Id, user.Username, editAttrs)
      const refreshed = await adminGetUser(userPool.Id, user.Username)
      setUser(refreshed)
      setEditAttrs(refreshed.Attributes || refreshed.UserAttributes || [])
      setEditing(false)
      setSuccess('Attributes updated')
      setTimeout(() => setSuccess(null), 3000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update attributes')
    } finally {
      setSaving(false)
    }
  }

  async function handleSetPassword() {
    if (!user || !newPassword) return
    try {
      setSaving(true)
      setError(null)
      await adminSetUserPassword(userPool.Id, user.Username, newPassword, passwordPermanent)
      setNewPassword('')
      setShowPasswordForm(false)
      const refreshed = await adminGetUser(userPool.Id, user.Username)
      setUser(refreshed)
      setSuccess('Password updated')
      setTimeout(() => setSuccess(null), 3000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to set password')
    } finally {
      setSaving(false)
    }
  }

  async function handleConfirm() {
    if (!user) return
    try {
      setError(null)
      await adminConfirmSignUp(userPool.Id, user.Username)
      const refreshed = await adminGetUser(userPool.Id, user.Username)
      setUser(refreshed)
      setSuccess('User confirmed')
      setTimeout(() => setSuccess(null), 3000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to confirm user')
    }
  }

  async function handleDelete() {
    if (!user) return
    if (!confirm(`Are you sure you want to delete "${user.Username}"?`)) return
    try {
      await adminDeleteUser(userPool.Id, user.Username)
      navigate(`/admin/pools/${userPool.Id}/users`)
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

  function updateAttr(index: number, value: string) {
    setEditAttrs(prev => prev.map((a, i) => i === index ? { ...a, Value: value } : a))
  }

  function removeAttr(index: number) {
    setEditAttrs(prev => prev.filter((_, i) => i !== index))
  }

  function addAttr() {
    if (!newAttrName.trim()) return
    setEditAttrs(prev => [...prev, { Name: newAttrName.trim(), Value: newAttrValue }])
    setNewAttrName('')
    setNewAttrValue('')
  }

  const isUnconfirmed = user?.UserStatus === 'UNCONFIRMED' || user?.UserStatus === 'FORCE_CHANGE_PASSWORD'
  const attrs = user?.Attributes || user?.UserAttributes || []

  return (
    <div class="max-w-6xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}`)}>{userPool.Name}</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}/users`)}>Users</button></li>
            <li>{initialUser.Username}</li>
          </ul>
        </div>
        <div class="flex justify-between items-center flex-wrap gap-4">
          <h1 class="text-3xl font-bold">{initialUser.Username}</h1>
          <div class="flex gap-3">
            {isUnconfirmed && (
              <button class="btn btn-success btn-outline btn-sm" onClick={handleConfirm}>Confirm</button>
            )}
            <button class="btn btn-outline btn-sm" onClick={handleToggleEnabled}>
              {user?.Enabled ? 'Disable' : 'Enable'}
            </button>
            <button class="btn btn-outline btn-sm" onClick={() => setShowPasswordForm(!showPasswordForm)}>
              Set Password
            </button>
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
      ) : user && (
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* User Information */}
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
                    <td>
                      <input type="checkbox" class="toggle toggle-sm toggle-success" checked={user.Enabled} onChange={handleToggleEnabled} />
                    </td>
                  </tr>
                  <tr><td class="font-medium text-base-content/60">Created</td><td>{formatDate(user.UserCreateDate)}</td></tr>
                  <tr><td class="font-medium text-base-content/60">Last Modified</td><td>{formatDate(user.UserLastModifiedDate)}</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Attributes */}
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <div class="flex justify-between items-center">
                <h2 class="card-title">Attributes</h2>
                {editing ? (
                  <div class="flex gap-2">
                    <button class="btn btn-primary btn-sm" onClick={handleSaveAttributes} disabled={saving}>
                      {saving ? <><span class="loading loading-spinner loading-sm"></span> Saving...</> : 'Save'}
                    </button>
                    <button class="btn btn-ghost btn-sm" onClick={cancelEditing}>Cancel</button>
                  </div>
                ) : (
                  <button class="btn btn-ghost btn-sm" onClick={startEditing}>Edit</button>
                )}
              </div>

              {editing ? (
                <>
                  <div class="space-y-3 mt-2">
                    {editAttrs.map((attr, i) => (
                      <div key={i} class="flex items-center gap-3">
                        <span class="font-medium text-sm text-base-content/60 w-32 shrink-0">{attr.Name}</span>
                        <input
                          type="text"
                          class="input input-bordered input-sm flex-1"
                          value={attr.Value}
                          onInput={e => updateAttr(i, (e.target as HTMLInputElement).value)}
                        />
                        <button class="btn btn-ghost btn-xs text-error" onClick={() => removeAttr(i)}>Remove</button>
                      </div>
                    ))}
                    <div class="flex items-center gap-3 pt-3 border-t border-base-200">
                      <input type="text" class="input input-bordered input-sm w-32 shrink-0" placeholder="Name" value={newAttrName} onInput={e => setNewAttrName((e.target as HTMLInputElement).value)} />
                      <input type="text" class="input input-bordered input-sm flex-1" placeholder="Value" value={newAttrValue} onInput={e => setNewAttrValue((e.target as HTMLInputElement).value)} />
                      <button class="btn btn-ghost btn-sm" onClick={addAttr} disabled={!newAttrName.trim()}>Add</button>
                    </div>
                  </div>
                </>
              ) : (
                attrs.length > 0 ? (
                  <table class="table table-sm">
                    <tbody>
                      {attrs.map(attr => (
                        <tr key={attr.Name}><td class="font-medium text-base-content/60 w-36">{attr.Name}</td><td class="break-all">{attr.Value}</td></tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p class="text-base-content/60 text-sm">No attributes</p>
                )
              )}
            </div>
          </div>

          {/* Set Password (collapsible) */}
          {showPasswordForm && (
            <div class="card bg-base-100 shadow lg:col-span-2">
              <div class="card-body">
                <h2 class="card-title">Set Password</h2>
                <div class="form-control mt-2">
                  <label class="label pb-1.5"><span class="label-text">New Password</span></label>
                  <input
                    type="password"
                    class="input input-bordered w-full"
                    placeholder="Enter new password"
                    value={newPassword}
                    onInput={e => setNewPassword((e.target as HTMLInputElement).value)}
                  />
                </div>
                <label class="flex items-center gap-3 cursor-pointer mt-4">
                  <input type="checkbox" class="checkbox checkbox-sm checkbox-primary" checked={passwordPermanent} onChange={() => setPasswordPermanent(!passwordPermanent)} />
                  <span class="label-text">Permanent (skip FORCE_CHANGE_PASSWORD)</span>
                </label>
                <div class="flex gap-3 mt-4">
                  <button class="btn btn-primary btn-sm" onClick={handleSetPassword} disabled={!newPassword || saving}>
                    {saving ? <><span class="loading loading-spinner loading-sm"></span> Setting...</> : 'Set Password'}
                  </button>
                  <button class="btn btn-ghost btn-sm" onClick={() => { setShowPasswordForm(false); setNewPassword('') }}>Cancel</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

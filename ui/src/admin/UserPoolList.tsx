import { useEffect, useState } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { formatDate } from '../lib/types'
import {
  API_BASE,
  adminCreateUser,
  adminDeleteUser,
  adminDisableUser,
  adminEnableUser,
  adminSetUserPassword,
  adminUpdateUserAttributes,
  createUserPool,
  createManagedLoginBranding,
  createUserPoolClient,
  deleteUserPool,
  deleteUserPoolClient,
  describeUserPool,
  listUserPools,
  listUserPoolClients,
  listUsers,
  updateManagedLoginBranding,
  updateUserPool,
  updateUserPoolClient,
} from '../lib/api'

interface UserPoolInspectorState {
  pool: UserPool | null
  users: User[]
  clients: UserPoolClient[]
}

interface UserPoolMetrics {
  users: number
  clients: number
}

type InspectorTab = 'users' | 'clients' | 'branding'

export function UserPoolList() {
  const [userPools, setUserPools] = useState<UserPool[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showEditPoolModal, setShowEditPoolModal] = useState(false)
  const [newPoolName, setNewPoolName] = useState('')
  const [editingPool, setEditingPool] = useState<UserPool | null>(null)
  const [editPoolName, setEditPoolName] = useState('')
  const [creating, setCreating] = useState(false)
  const [poolUpdating, setPoolUpdating] = useState(false)
  const [poolMetrics, setPoolMetrics] = useState<Record<string, UserPoolMetrics>>({})
  const [selectedPoolId, setSelectedPoolId] = useState<string | null>(null)
  const [isInspectorOpen, setIsInspectorOpen] = useState(false)
  const [inspectorLoading, setInspectorLoading] = useState(false)
  const [inspectorError, setInspectorError] = useState<string | null>(null)
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('users')
  const [inspectorState, setInspectorState] = useState<UserPoolInspectorState>({ pool: null, users: [], clients: [] })
  const [showCreateUserModal, setShowCreateUserModal] = useState(false)
  const [showEditUserModal, setShowEditUserModal] = useState(false)
  const [showCreateClientModal, setShowCreateClientModal] = useState(false)
  const [showEditClientModal, setShowEditClientModal] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [editEmail, setEditEmail] = useState('')
  const [editPassword, setEditPassword] = useState('')
  const [editPasswordPermanent, setEditPasswordPermanent] = useState(true)
  const [newClientName, setNewClientName] = useState('')
  const [newCallbackUrls, setNewCallbackUrls] = useState('')
  const [editingClient, setEditingClient] = useState<UserPoolClient | null>(null)
  const [editClientName, setEditClientName] = useState('')
  const [editCallbackUrls, setEditCallbackUrls] = useState('')
  const [userSubmitting, setUserSubmitting] = useState(false)
  const [clientSubmitting, setClientSubmitting] = useState(false)
  const [brandingClientId, setBrandingClientId] = useState('')
  const [brandingId, setBrandingId] = useState<string | null>(null)
  const [brandingSaving, setBrandingSaving] = useState(false)
  const [brandingSuccess, setBrandingSuccess] = useState<string | null>(null)
  const [pageTitle, setPageTitle] = useState('Sign In')
  const [signInHeader, setSignInHeader] = useState('Welcome')
  const [signInSubheader, setSignInSubheader] = useState('Sign in to continue')
  const [backgroundColor, setBackgroundColor] = useState('#f5f5f5')
  const [primaryColor, setPrimaryColor] = useState('#007bff')
  const [textColor, setTextColor] = useState('#333333')
  const [buttonColor, setButtonColor] = useState('#007bff')
  const [buttonTextColor, setButtonTextColor] = useState('#ffffff')

  const sortedUserPools = [...userPools].sort((left, right) => Number(right.LastModifiedDate) - Number(left.LastModifiedDate))
  const inspectorPool = inspectorState.pool

  useEffect(() => {
    listUserPools()
      .then(pools => setUserPools(pools))
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load user pools'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (userPools.length === 0) {
      setPoolMetrics({})
      return
    }

    let cancelled = false

    void Promise.all(
      userPools.map(async pool => {
        const [users, clients] = await Promise.all([
          listUsers(pool.Id),
          listUserPoolClients(pool.Id),
        ])
        return [pool.Id, { users: users.length, clients: clients.length }] as const
      })
    )
      .then(entries => {
        if (cancelled) return
        setPoolMetrics(Object.fromEntries(entries))
      })
      .catch(() => {
        if (cancelled) return
        setPoolMetrics(current => current)
      })

    return () => {
      cancelled = true
    }
  }, [userPools])

  useEffect(() => {
    if (
      !isInspectorOpen ||
      showCreateModal ||
      showEditPoolModal ||
      showCreateUserModal ||
      showEditUserModal ||
      showCreateClientModal ||
      showEditClientModal
    ) {
      return
    }

    function handleKeydown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        closeInspector()
      }
    }

    window.addEventListener('keydown', handleKeydown)
    return () => {
      window.removeEventListener('keydown', handleKeydown)
    }
  }, [
    isInspectorOpen,
    showCreateModal,
    showEditPoolModal,
    showCreateUserModal,
    showEditUserModal,
    showCreateClientModal,
    showEditClientModal,
  ])

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newPoolName.trim()) return
    try {
      setCreating(true)
      const pool = await createUserPool(newPoolName.trim())
      setUserPools(prev => [...prev, pool])
      setPoolMetrics(prev => ({ ...prev, [pool.Id]: { users: 0, clients: 0 } }))
      setShowCreateModal(false)
      setNewPoolName('')
      void openInspector(pool)
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
      setPoolMetrics(prev => {
        const next = { ...prev }
        delete next[pool.Id]
        return next
      })
      if (selectedPoolId === pool.Id) clearSelectedPool()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete user pool')
    }
  }

  async function loadPoolContext(pool: UserPool) {
    setSelectedPoolId(pool.Id)
    setInspectorError(null)
    setInspectorLoading(true)

    try {
      const [poolDetails, users, clients] = await Promise.all([
        describeUserPool(pool.Id),
        listUsers(pool.Id),
        listUserPoolClients(pool.Id),
      ])
      setInspectorState({ pool: poolDetails, users, clients })
      setPoolMetrics(prev => ({
        ...prev,
        [pool.Id]: { users: users.length, clients: clients.length },
      }))
      setBrandingClientId(clients[0]?.ClientId || '')
      setBrandingId(null)
      setBrandingSuccess(null)
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to load user pool details')
      setInspectorState({ pool, users: [], clients: [] })
      setBrandingClientId('')
    } finally {
      setInspectorLoading(false)
    }
  }

  async function openInspector(pool: UserPool, tab: InspectorTab = 'users') {
    setInspectorTab(tab)
    setIsInspectorOpen(true)
    await loadPoolContext(pool)
  }

  function clearSelectedPool() {
    setSelectedPoolId(null)
    setIsInspectorOpen(false)
    setInspectorError(null)
    setInspectorLoading(false)
    setInspectorTab('users')
    setInspectorState({ pool: null, users: [], clients: [] })
    setShowEditPoolModal(false)
    setEditingPool(null)
    setShowCreateUserModal(false)
    setShowEditUserModal(false)
    setShowCreateClientModal(false)
    setShowEditClientModal(false)
    setBrandingClientId('')
    setBrandingId(null)
    setBrandingSuccess(null)
  }

  function closeInspector() {
    setIsInspectorOpen(false)
    setInspectorError(null)
    setShowEditPoolModal(false)
    setEditingPool(null)
    setShowCreateUserModal(false)
    setShowEditUserModal(false)
    setShowCreateClientModal(false)
    setShowEditClientModal(false)
  }

  function poolStatusLabel(status?: string) {
    if (status === 'ACTIVE') return '[ ACTIVE ]'
    if (status === 'DELETING') return '[ DELETING ]'
    return status ? `[ ${status} ]` : '-'
  }

  function poolStatusClass(status?: string) {
    if (status === 'ACTIVE') return 'text-emerald-600'
    if (status === 'DELETING') return 'text-amber-600'
    return 'text-slate-500'
  }

  function userStatusClass(status: string) {
    return status === 'CONFIRMED' ? 'text-emerald-600' : 'text-amber-600'
  }

  function userStatusLabel(status: string) {
    if (status === 'CONFIRMED') return '[ CONFIRMED ]'
    if (status === 'UNCONFIRMED') return '[ UNCONFIRMED ]'
    if (status === 'FORCE_CHANGE_PASSWORD') return '[ FORCE CHANGE ]'
    return `[ ${status.replaceAll('_', ' ')} ]`
  }

  function getEmail(user: User) {
    return user.Attributes?.find(attribute => attribute.Name === 'email')?.Value || '-'
  }

  function openEditPoolModal(pool: UserPool) {
    setEditingPool(pool)
    setEditPoolName(pool.Name)
    setShowEditPoolModal(true)
  }

  async function handleUpdatePool(e: Event) {
    e.preventDefault()
    if (!editingPool || !editPoolName.trim()) return
    try {
      setPoolUpdating(true)
      await updateUserPool(editingPool.Id, { PoolName: editPoolName.trim() })

      const lastModifiedDate = String(Math.floor(Date.now() / 1000))
      setUserPools(prev =>
        prev.map(pool =>
          pool.Id === editingPool.Id
            ? { ...pool, Name: editPoolName.trim(), LastModifiedDate: lastModifiedDate }
            : pool
        )
      )

      setInspectorState(prev => ({
        ...prev,
        pool:
          prev.pool && prev.pool.Id === editingPool.Id
            ? { ...prev.pool, Name: editPoolName.trim(), LastModifiedDate: lastModifiedDate }
            : prev.pool,
      }))

      setShowEditPoolModal(false)
      setEditingPool(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update user pool')
    } finally {
      setPoolUpdating(false)
    }
  }

  function openEditUserModal(user: User) {
    setEditingUser(user)
    setEditEmail(getEmail(user) === '-' ? '' : getEmail(user))
    setEditPassword('')
    setEditPasswordPermanent(true)
    setShowEditUserModal(true)
  }

  function openEditClientModal(client: UserPoolClient) {
    setEditingClient(client)
    setEditClientName(client.ClientName)
    setEditCallbackUrls((client.CallbackURLs || []).join('\n'))
    setShowEditClientModal(true)
  }

  async function handleCreateUser(e: Event) {
    e.preventDefault()
    if (!inspectorPool || !newUsername.trim() || !newEmail.trim()) return
    try {
      setUserSubmitting(true)
      const createdUser = await adminCreateUser(
        inspectorPool.Id,
        newUsername.trim(),
        newEmail.trim(),
        newPassword.trim() || undefined
      )
      setInspectorState(prev => ({ ...prev, users: [...prev.users, createdUser] }))
      setPoolMetrics(prev => ({
        ...prev,
        [inspectorPool.Id]: {
          users: (prev[inspectorPool.Id]?.users || 0) + 1,
          clients: prev[inspectorPool.Id]?.clients || inspectorState.clients.length,
        },
      }))
      setShowCreateUserModal(false)
      setNewUsername('')
      setNewEmail('')
      setNewPassword('')
      setInspectorTab('users')
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to create user')
    } finally {
      setUserSubmitting(false)
    }
  }

  async function handleUpdateUser(e: Event) {
    e.preventDefault()
    if (!inspectorPool || !editingUser || !editEmail.trim()) return
    try {
      setUserSubmitting(true)

      const tasks: Promise<void>[] = []
      tasks.push(
        adminUpdateUserAttributes(inspectorPool.Id, editingUser.Username, [
          { Name: 'email', Value: editEmail.trim() },
        ])
      )

      if (editPassword.trim()) {
        tasks.push(adminSetUserPassword(inspectorPool.Id, editingUser.Username, editPassword.trim(), editPasswordPermanent))
      }

      await Promise.all(tasks)

      setInspectorState(prev => ({
        ...prev,
        users: prev.users.map(current => {
          if (current.Username !== editingUser.Username) return current
          const nextAttributes = current.Attributes.some(attribute => attribute.Name === 'email')
            ? current.Attributes.map(attribute =>
                attribute.Name === 'email' ? { ...attribute, Value: editEmail.trim() } : attribute
              )
            : [...current.Attributes, { Name: 'email', Value: editEmail.trim() }]

          return {
            ...current,
            Attributes: nextAttributes,
            UserStatus: editPassword.trim()
              ? (editPasswordPermanent ? 'CONFIRMED' : 'FORCE_CHANGE_PASSWORD')
              : current.UserStatus,
          }
        }),
      }))

      setShowEditUserModal(false)
      setEditingUser(null)
      setEditPassword('')
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to update user')
    } finally {
      setUserSubmitting(false)
    }
  }

  async function handleDeleteUser(user: User) {
    if (!inspectorPool) return
    if (!confirm(`Are you sure you want to delete "${user.Username}"?`)) return
    try {
      await adminDeleteUser(inspectorPool.Id, user.Username)
      setInspectorState(prev => ({
        ...prev,
        users: prev.users.filter(current => current.Username !== user.Username),
      }))
      setPoolMetrics(prev => ({
        ...prev,
        [inspectorPool.Id]: {
          users: Math.max((prev[inspectorPool.Id]?.users || inspectorState.users.length) - 1, 0),
          clients: prev[inspectorPool.Id]?.clients || inspectorState.clients.length,
        },
      }))
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to delete user')
    }
  }

  async function handleToggleUserEnabled(user: User) {
    if (!inspectorPool) return
    try {
      if (user.Enabled) {
        await adminDisableUser(inspectorPool.Id, user.Username)
      } else {
        await adminEnableUser(inspectorPool.Id, user.Username)
      }
      setInspectorState(prev => ({
        ...prev,
        users: prev.users.map(current =>
          current.Username === user.Username ? { ...current, Enabled: !current.Enabled } : current
        ),
      }))
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to update user')
    }
  }

  async function handleCreateClient(e: Event) {
    e.preventDefault()
    if (!inspectorPool || !newClientName.trim()) return
    try {
      setClientSubmitting(true)
      const callbackUrls = newCallbackUrls
        .split('\n')
        .map(value => value.trim())
        .filter(Boolean)
      const createdClient = await createUserPoolClient(
        inspectorPool.Id,
        newClientName.trim(),
        callbackUrls.length > 0 ? callbackUrls : undefined,
        ['code'],
        ['openid', 'email', 'profile']
      )
      setInspectorState(prev => ({ ...prev, clients: [...prev.clients, createdClient] }))
      setPoolMetrics(prev => ({
        ...prev,
        [inspectorPool.Id]: {
          users: prev[inspectorPool.Id]?.users || inspectorState.users.length,
          clients: (prev[inspectorPool.Id]?.clients || 0) + 1,
        },
      }))
      setShowCreateClientModal(false)
      setNewClientName('')
      setNewCallbackUrls('')
      setInspectorTab('clients')
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to create client')
    } finally {
      setClientSubmitting(false)
    }
  }

  async function handleDeleteClient(client: UserPoolClient) {
    if (!inspectorPool) return
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return
    try {
      await deleteUserPoolClient(inspectorPool.Id, client.ClientId)
      setInspectorState(prev => ({
        ...prev,
        clients: prev.clients.filter(current => current.ClientId !== client.ClientId),
      }))
      setPoolMetrics(prev => ({
        ...prev,
        [inspectorPool.Id]: {
          users: prev[inspectorPool.Id]?.users || inspectorState.users.length,
          clients: Math.max((prev[inspectorPool.Id]?.clients || inspectorState.clients.length) - 1, 0),
        },
      }))
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to delete client')
    }
  }

  async function handleUpdateClient(e: Event) {
    e.preventDefault()
    if (!inspectorPool || !editingClient || !editClientName.trim()) return
    try {
      setClientSubmitting(true)
      const callbackUrls = editCallbackUrls
        .split('\n')
        .map(value => value.trim())
        .filter(Boolean)

      const updatedClient = await updateUserPoolClient(inspectorPool.Id, editingClient.ClientId, {
        ClientName: editClientName.trim(),
        CallbackURLs: callbackUrls,
        AllowedOAuthFlowsUserPoolClient: callbackUrls.length > 0,
      })

      setInspectorState(prev => ({
        ...prev,
        clients: prev.clients.map(current => (current.ClientId === editingClient.ClientId ? updatedClient : current)),
      }))
      setShowEditClientModal(false)
      setEditingClient(null)
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to update client')
    } finally {
      setClientSubmitting(false)
    }
  }

  function tabClass(tab: InspectorTab) {
    return `tab ${inspectorTab === tab ? 'tab-active' : ''}`
  }

  const colorFields = [
    { label: 'Background', value: backgroundColor, setter: setBackgroundColor },
    { label: 'Primary', value: primaryColor, setter: setPrimaryColor },
    { label: 'Text', value: textColor, setter: setTextColor },
    { label: 'Button', value: buttonColor, setter: setButtonColor },
    { label: 'Button text', value: buttonTextColor, setter: setButtonTextColor },
  ]

  async function handleSaveBranding() {
    if (!inspectorPool) return
    if (!brandingClientId) {
      setInspectorError('Please select a client')
      return
    }
    try {
      setBrandingSaving(true)
      setInspectorError(null)
      const settings = {
        PageTitle: pageTitle,
        SignInHeader: signInHeader,
        SignInSubheader: signInSubheader,
        Colors: {
          BackgroundColor: backgroundColor,
          PrimaryColor: primaryColor,
          TextColor: textColor,
          ButtonColor: buttonColor,
          ButtonTextColor: buttonTextColor,
        },
      }
      if (brandingId) {
        await updateManagedLoginBranding(inspectorPool.Id, brandingId, settings)
      } else {
        const branding = await createManagedLoginBranding(inspectorPool.Id, brandingClientId, settings)
        setBrandingId(branding.ManagedLoginBrandingId)
      }
      setBrandingSuccess('Branding saved')
      setTimeout(() => setBrandingSuccess(null), 3000)
    } catch (e) {
      setInspectorError(e instanceof Error ? e.message : 'Failed to save branding')
    } finally {
      setBrandingSaving(false)
    }
  }

  function getBrandingPreviewUrl() {
    if (!brandingClientId) return ''
    const client = inspectorState.clients.find(current => current.ClientId === brandingClientId)
    const callbackUrl = client?.CallbackURLs?.[0] || 'http://localhost:3000/callback'
    return `${API_BASE}/ui/?response_type=code&client_id=${brandingClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
  }

  function renderUserPoolsTable() {
    return (
      <section class="rounded-box border border-slate-200 bg-white">
        <div class="overflow-x-auto">
          <table class="table w-full min-w-[34rem] sm:min-w-[42rem] lg:min-w-[68rem]">
            <thead>
              <tr>
                <th>Name</th>
                <th class="hidden sm:table-cell">Pool ID</th>
                <th>Users</th>
                <th>Clients</th>
                <th class="hidden md:table-cell">Status</th>
                <th class="hidden lg:table-cell">Domain</th>
                <th class="hidden lg:table-cell">Created</th>
                <th class="hidden lg:table-cell">Modified</th>
                <th class="w-px whitespace-nowrap">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={9} class="px-4 py-10 text-center text-slate-500">
                    Loading user pools...
                  </td>
                </tr>
              ) : sortedUserPools.length === 0 ? (
                <tr>
                  <td colSpan={9} class="px-4 py-10">
                    <div class="flex flex-col items-start justify-between gap-4 md:flex-row md:items-center">
                      <div>
                        <div class="text-slate-900">No user pools yet</div>
                        <p class="mt-1 text-sm text-slate-500">Create your first user pool to start testing users, clients, and hosted UI flows.</p>
                      </div>
                      <button class="btn btn-sm" onClick={() => setShowCreateModal(true)}>Create</button>
                    </div>
                  </td>
                </tr>
              ) : (
                sortedUserPools.map(pool => (
                  <tr
                    key={pool.Id}
                    class={`${selectedPoolId === pool.Id ? 'admin-row-selected ' : ''}cursor-pointer`}
                    onClick={() => void openInspector(pool)}
                  >
                    <td class="min-w-56">
                      <button
                        class="btn btn-link btn-sm inline-flex max-w-64 justify-start px-0 text-slate-900 no-underline hover:no-underline"
                        title={pool.Name}
                        onClick={e => {
                          e.stopPropagation()
                          void openInspector(pool)
                        }}
                      >
                        <span class="truncate">{pool.Name}</span>
                      </button>
                    </td>
                    <td class="hidden text-slate-500 sm:table-cell">
                      <code class="text-xs">{pool.Id}</code>
                    </td>
                    <td class="text-slate-500">{poolMetrics[pool.Id]?.users ?? '-'}</td>
                    <td class="text-slate-500">{poolMetrics[pool.Id]?.clients ?? '-'}</td>
                    <td class={`${poolStatusClass(pool.Status)} hidden md:table-cell`}>{poolStatusLabel(pool.Status)}</td>
                    <td class="hidden text-slate-500 lg:table-cell">{pool.CustomDomain || pool.Domain || '-'}</td>
                    <td class="hidden text-slate-500 lg:table-cell">{formatDate(pool.CreationDate)}</td>
                    <td class="hidden text-slate-500 lg:table-cell">{formatDate(pool.LastModifiedDate)}</td>
                    <td>
                      <div class="flex justify-end gap-2 whitespace-nowrap">
                        <button
                          class="btn btn-ghost btn-sm"
                          onClick={e => {
                            e.stopPropagation()
                            openEditPoolModal(pool)
                          }}
                        >
                          Edit
                        </button>
                        <button
                          class="btn btn-ghost btn-sm text-red-600 hover:bg-red-50"
                          onClick={e => {
                            e.stopPropagation()
                            void handleDelete(pool)
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    )
  }

  function renderUsersTable(compact = false) {
    return (
      <section class="rounded-box border border-slate-200 bg-white">
        <div class="flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 text-sm text-slate-500">
          <span>{inspectorState.users.length} users</span>
          <button class="btn btn-sm" onClick={() => setShowCreateUserModal(true)}>Create</button>
        </div>
        <div class={compact ? 'max-h-[28rem] overflow-auto' : 'overflow-x-auto'}>
          <table class="table w-full min-w-[36rem] sm:min-w-[44rem]">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Status</th>
                <th>Enabled</th>
                <th class="w-px whitespace-nowrap">Actions</th>
              </tr>
            </thead>
            <tbody>
              {inspectorState.users.length === 0 ? (
                <tr>
                  <td colSpan={5} class="px-4 py-6 text-sm text-slate-500">No users yet</td>
                </tr>
              ) : (
                inspectorState.users.map(user => (
                  <tr key={user.Username} class="cursor-pointer" onClick={() => openEditUserModal(user)}>
                    <td class="max-w-48 text-slate-900" title={user.Username}><div class="truncate">{user.Username}</div></td>
                    <td class="max-w-56 text-slate-500" title={getEmail(user)}><div class="truncate">{getEmail(user)}</div></td>
                    <td class={`${userStatusClass(user.UserStatus)} whitespace-nowrap text-xs`}>
                      {userStatusLabel(user.UserStatus)}
                    </td>
                    <td class="text-slate-500">{user.Enabled ? 'Enabled' : 'Disabled'}</td>
                    <td>
                      <div class="flex justify-end gap-2 whitespace-nowrap">
                        <button class="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); openEditUserModal(user) }}>
                          Edit
                        </button>
                        <button class="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); void handleToggleUserEnabled(user) }}>
                          {user.Enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button class="btn btn-ghost btn-sm text-red-600 hover:bg-red-50" onClick={e => { e.stopPropagation(); void handleDeleteUser(user) }}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    )
  }

  function renderClientsTable(compact = false) {
    return (
      <section class="rounded-box border border-slate-200 bg-white">
        <div class="flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 text-sm text-slate-500">
          <span>{inspectorState.clients.length} clients</span>
          <button class="btn btn-sm" onClick={() => setShowCreateClientModal(true)}>Create</button>
        </div>
        <div class={compact ? 'max-h-[28rem] overflow-auto' : 'overflow-x-auto'}>
          <table class="table w-full min-w-[32rem] sm:min-w-[38rem]">
            <thead>
              <tr>
                <th>Name</th>
                <th>Client ID</th>
                <th>Flows</th>
                <th class="w-px whitespace-nowrap">Actions</th>
              </tr>
            </thead>
            <tbody>
              {inspectorState.clients.length === 0 ? (
                <tr>
                  <td colSpan={4} class="px-4 py-6 text-sm text-slate-500">No app clients yet</td>
                </tr>
              ) : (
                inspectorState.clients.map(client => (
                  <tr key={client.ClientId} class="cursor-pointer" onClick={() => openEditClientModal(client)}>
                    <td class="max-w-48 text-slate-900" title={client.ClientName}><div class="truncate">{client.ClientName}</div></td>
                    <td><code class="text-xs text-slate-500">{client.ClientId}</code></td>
                    <td class="text-slate-500">{client.AllowedOAuthFlows?.join(', ') || '-'}</td>
                    <td>
                      <div class="flex justify-end gap-2 whitespace-nowrap">
                        <button class="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); openEditClientModal(client) }}>
                          Edit
                        </button>
                        <button class="btn btn-ghost btn-sm text-red-600 hover:bg-red-50" onClick={e => { e.stopPropagation(); void handleDeleteClient(client) }}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    )
  }

  return (
    <>
      <div class="w-full">
        <div class="mb-4 flex items-center justify-between gap-3 border-b border-slate-200 pb-4 sm:mb-6">
          <div class="space-y-1">
            <h1 class="text-xl text-slate-900">User Pools</h1>
          </div>
          <button class="btn btn-sm shrink-0" onClick={() => setShowCreateModal(true)}>Create</button>
        </div>

        {error && (
          <div class="alert alert-error mb-6">
            <span>{error}</span>
            <button class="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}

        {renderUserPoolsTable()}

        {showCreateModal && (
          <dialog class="modal modal-open">
            <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
              <h3 class="mb-4 text-lg text-slate-900">Create user pool</h3>
              <form onSubmit={handleCreate}>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Pool name</legend>
                  <input
                    type="text"
                    class="input input-bordered w-full"
                    placeholder="my-user-pool"
                    value={newPoolName}
                    onInput={e => setNewPoolName((e.target as HTMLInputElement).value)}
                    disabled={creating}
                    required
                  />
                </fieldset>
                <div class="modal-action mt-6">
                  <button type="button" class="btn btn-ghost" onClick={() => setShowCreateModal(false)} disabled={creating}>Cancel</button>
                  <button type="submit" class="btn" disabled={creating}>
                    {creating ? 'Creating...' : 'Create'}
                  </button>
                </div>
              </form>
            </div>
            <form method="dialog" class="modal-backdrop"><button onClick={() => setShowCreateModal(false)}>close</button></form>
          </dialog>
        )}

        {showEditPoolModal && editingPool && (
          <dialog class="modal modal-open">
            <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
              <h3 class="mb-4 text-lg text-slate-900">Edit user pool</h3>
              <form onSubmit={handleUpdatePool}>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Pool name</legend>
                  <input
                    type="text"
                    class="input input-bordered w-full"
                    value={editPoolName}
                    onInput={e => setEditPoolName((e.target as HTMLInputElement).value)}
                    disabled={poolUpdating}
                    required
                  />
                </fieldset>
                <div class="modal-action mt-6">
                  <button
                    type="button"
                    class="btn"
                    onClick={() => {
                      setShowEditPoolModal(false)
                      setEditingPool(null)
                    }}
                    disabled={poolUpdating}
                  >
                    Cancel
                  </button>
                  <button type="submit" class="btn" disabled={poolUpdating}>
                    {poolUpdating ? 'Saving...' : 'Save'}
                  </button>
                </div>
              </form>
            </div>
            <form method="dialog" class="modal-backdrop">
              <button
                onClick={() => {
                  setShowEditPoolModal(false)
                  setEditingPool(null)
                }}
              >
                close
              </button>
            </form>
          </dialog>
        )}
      </div>

      {isInspectorOpen && <div class="admin-sidepeek-backdrop" onClick={closeInspector} />}

      <aside class={`admin-sidepeek ${isInspectorOpen ? 'admin-sidepeek-open' : ''}`}>
        <div class="flex items-start justify-between gap-4 px-5 py-4">
          <div>
            <h2 class="max-w-[24rem] truncate text-lg text-slate-900" title={inspectorPool?.Name || 'Loading'}>
              {inspectorPool?.Name || 'Loading'}
            </h2>
            {inspectorPool && <div class="mt-1 max-w-[24rem] truncate text-sm text-slate-500" title={inspectorPool.Id}>{inspectorPool.Id}</div>}
          </div>
          <div class="flex items-center gap-2">
            <button class="btn btn-ghost btn-sm" onClick={closeInspector}>Close</button>
          </div>
        </div>

        <div class="px-5 py-3">
          <div class="tabs tabs-box gap-2 bg-transparent p-0">
            <button class={tabClass('users')} onClick={() => setInspectorTab('users')}>Users</button>
            <button class={tabClass('clients')} onClick={() => setInspectorTab('clients')}>Clients</button>
            <button class={tabClass('branding')} onClick={() => setInspectorTab('branding')}>Branding</button>
          </div>
        </div>

        <div class="flex flex-col gap-5 px-5 py-5">
          {inspectorError && (
            <div class="alert alert-error">
              <span>{inspectorError}</span>
            </div>
          )}

          {inspectorLoading ? (
            <div class="rounded-box border border-slate-200 bg-slate-50 px-4 py-8 text-sm text-slate-500">
              Loading details...
            </div>
          ) : inspectorPool ? (
            <>
              {inspectorTab === 'users' && (
                renderUsersTable(true)
              )}

              {inspectorTab === 'clients' && (
                renderClientsTable(true)
              )}

              {inspectorTab === 'branding' && (
                <section class="rounded-box border border-slate-200 bg-white">
                  <div class="border-b border-slate-200 bg-white px-4 py-3 text-sm text-slate-500">Branding</div>
                  <div class="space-y-4 p-4">
                    {brandingSuccess && <div class="alert alert-success"><span>{brandingSuccess}</span></div>}

                    {inspectorState.clients.length === 0 ? (
                      <div class="rounded-box border border-slate-200 bg-slate-50 px-4 py-6 text-sm text-slate-500">
                        Create a client first to edit branding.
                      </div>
                    ) : (
                      <>
                        <fieldset class="fieldset">
                          <legend class="fieldset-legend">Client</legend>
                          <select class="select select-bordered w-full" value={brandingClientId} onChange={e => setBrandingClientId((e.target as HTMLSelectElement).value)}>
                            {inspectorState.clients.map(client => (
                              <option key={client.ClientId} value={client.ClientId}>{client.ClientName}</option>
                            ))}
                          </select>
                        </fieldset>

                        <fieldset class="fieldset">
                          <legend class="fieldset-legend">Page title</legend>
                          <input type="text" class="input input-bordered w-full" value={pageTitle} onInput={e => setPageTitle((e.target as HTMLInputElement).value)} />
                        </fieldset>

                        <fieldset class="fieldset">
                          <legend class="fieldset-legend">Sign in header</legend>
                          <input type="text" class="input input-bordered w-full" value={signInHeader} onInput={e => setSignInHeader((e.target as HTMLInputElement).value)} />
                        </fieldset>

                        <fieldset class="fieldset">
                          <legend class="fieldset-legend">Sign in subheader</legend>
                          <input type="text" class="input input-bordered w-full" value={signInSubheader} onInput={e => setSignInSubheader((e.target as HTMLInputElement).value)} />
                        </fieldset>

                        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                          {colorFields.map(({ label, value, setter }) => (
                            <fieldset key={label} class="fieldset">
                              <legend class="fieldset-legend">{label}</legend>
                              <div class="flex gap-2">
                                <input type="color" class="h-10 w-12 cursor-pointer rounded-box border border-slate-200 bg-white" value={value} onInput={e => setter((e.target as HTMLInputElement).value)} />
                                <input type="text" class="input input-bordered w-full font-mono" value={value} onInput={e => setter((e.target as HTMLInputElement).value)} />
                              </div>
                            </fieldset>
                          ))}
                        </div>

                        <div class="rounded-box border border-slate-200 p-4" style={{ backgroundColor }}>
                          <div class="mx-auto w-full max-w-xs rounded-box border border-slate-200 bg-white p-6">
                            <h3 class="mb-2 text-center text-lg" style={{ color: textColor }}>{signInHeader}</h3>
                            <p class="mb-5 text-center text-sm" style={{ color: textColor, opacity: 0.7 }}>{signInSubheader}</p>
                            <div class="mb-3 rounded-box bg-slate-100 px-3 py-2 text-sm text-slate-400">Username</div>
                            <div class="mb-3 rounded-box bg-slate-100 px-3 py-2 text-sm text-slate-400">Password</div>
                            <div class="rounded-box px-3 py-2 text-center text-sm" style={{ backgroundColor: buttonColor, color: buttonTextColor }}>
                              Sign In
                            </div>
                          </div>
                        </div>

                        <div class="flex flex-wrap gap-2">
                          <button class="btn btn-sm" onClick={handleSaveBranding} disabled={brandingSaving}>
                            {brandingSaving ? 'Saving...' : 'Save branding'}
                          </button>
                          {brandingClientId && (
                            <a href={getBrandingPreviewUrl()} target="_blank" rel="noopener" class="btn btn-ghost btn-sm">
                              Preview
                            </a>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                </section>
              )}
            </>
          ) : null}
        </div>
      </aside>

      {showCreateUserModal && inspectorPool && (
        <dialog class="modal modal-open">
            <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
              <h3 class="mb-4 text-lg text-slate-900">Create user</h3>
              <form onSubmit={handleCreateUser}>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Username</legend>
                  <input
                    type="text"
                    class="input input-bordered w-full"
                    value={newUsername}
                    onInput={e => setNewUsername((e.target as HTMLInputElement).value)}
                    disabled={userSubmitting}
                    required
                  />
                </fieldset>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Email</legend>
                  <input
                    type="email"
                    class="input input-bordered w-full"
                    value={newEmail}
                    onInput={e => setNewEmail((e.target as HTMLInputElement).value)}
                    disabled={userSubmitting}
                    required
                  />
                </fieldset>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Temporary password</legend>
                  <input
                    type="password"
                    class="input input-bordered w-full"
                    value={newPassword}
                    onInput={e => setNewPassword((e.target as HTMLInputElement).value)}
                    disabled={userSubmitting}
                  />
                </fieldset>
              <div class="modal-action mt-6">
                <button type="button" class="btn btn-ghost" onClick={() => setShowCreateUserModal(false)} disabled={userSubmitting}>Cancel</button>
                <button type="submit" class="btn" disabled={userSubmitting}>
                  {userSubmitting ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
          <form method="dialog" class="modal-backdrop"><button onClick={() => setShowCreateUserModal(false)}>close</button></form>
        </dialog>
      )}

      {showCreateClientModal && inspectorPool && (
        <dialog class="modal modal-open">
            <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
              <h3 class="mb-4 text-lg text-slate-900">Create client</h3>
            <form onSubmit={handleCreateClient}>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Client name</legend>
                  <input
                    type="text"
                    class="input input-bordered w-full"
                    value={newClientName}
                    onInput={e => setNewClientName((e.target as HTMLInputElement).value)}
                    disabled={clientSubmitting}
                    required
                  />
                </fieldset>
                <fieldset class="fieldset mb-4">
                  <legend class="fieldset-legend">Callback URLs</legend>
                  <label class="label pt-0">
                    <span class="label-text-alt text-slate-500">One URL per line</span>
                  </label>
                  <textarea
                    class="textarea textarea-bordered w-full"
                    rows={4}
                    value={newCallbackUrls}
                    onInput={e => setNewCallbackUrls((e.target as HTMLTextAreaElement).value)}
                    disabled={clientSubmitting}
                    placeholder="http://localhost:3000/callback"
                  />
                </fieldset>
              <div class="modal-action mt-6">
                <button type="button" class="btn btn-ghost" onClick={() => setShowCreateClientModal(false)} disabled={clientSubmitting}>Cancel</button>
                <button type="submit" class="btn" disabled={clientSubmitting}>
                  {clientSubmitting ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
          <form method="dialog" class="modal-backdrop"><button onClick={() => setShowCreateClientModal(false)}>close</button></form>
        </dialog>
      )}

      {showEditUserModal && inspectorPool && editingUser && (
        <dialog class="modal modal-open">
          <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
            <h3 class="mb-4 text-lg text-slate-900">Edit user</h3>
            <form onSubmit={handleUpdateUser}>
              <fieldset class="fieldset mb-4">
                <legend class="fieldset-legend">Username</legend>
                <input type="text" class="input input-bordered w-full" value={editingUser.Username} disabled />
              </fieldset>
              <fieldset class="fieldset mb-4">
                <legend class="fieldset-legend">Email</legend>
                <input
                  type="email"
                  class="input input-bordered w-full"
                  value={editEmail}
                  onInput={e => setEditEmail((e.target as HTMLInputElement).value)}
                  disabled={userSubmitting}
                  required
                />
              </fieldset>
              <fieldset class="fieldset mb-4">
                <legend class="fieldset-legend">New password</legend>
                <input
                  type="password"
                  class="input input-bordered w-full"
                  value={editPassword}
                  onInput={e => setEditPassword((e.target as HTMLInputElement).value)}
                  disabled={userSubmitting}
                  placeholder="Leave empty to keep current password"
                />
              </fieldset>
              <fieldset class="fieldset mb-4">
                <label class="label cursor-pointer justify-start gap-3">
                  <input
                    type="checkbox"
                    class="checkbox checkbox-sm"
                    checked={editPasswordPermanent}
                    onChange={e => setEditPasswordPermanent((e.target as HTMLInputElement).checked)}
                    disabled={userSubmitting || !editPassword.trim()}
                  />
                  <span class="label-text">Set as permanent password</span>
                </label>
              </fieldset>
              <div class="modal-action mt-6">
                <button type="button" class="btn btn-ghost" onClick={() => setShowEditUserModal(false)} disabled={userSubmitting}>Cancel</button>
                <button type="submit" class="btn" disabled={userSubmitting}>
                  {userSubmitting ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          </div>
          <form method="dialog" class="modal-backdrop"><button onClick={() => setShowEditUserModal(false)}>close</button></form>
        </dialog>
      )}

      {showEditClientModal && inspectorPool && editingClient && (
        <dialog class="modal modal-open">
          <div class="modal-box max-w-md border border-slate-200 bg-white p-6">
            <h3 class="mb-4 text-lg text-slate-900">Edit client</h3>
            <form onSubmit={handleUpdateClient}>
              <fieldset class="fieldset mb-4">
                <legend class="fieldset-legend">Client name</legend>
                <input
                  type="text"
                  class="input input-bordered w-full"
                  value={editClientName}
                  onInput={e => setEditClientName((e.target as HTMLInputElement).value)}
                  disabled={clientSubmitting}
                  required
                />
              </fieldset>
              <fieldset class="fieldset mb-4">
                <legend class="fieldset-legend">Callback URLs</legend>
                <label class="label pt-0">
                  <span class="label-text-alt text-slate-500">One URL per line</span>
                </label>
                <textarea
                  class="textarea textarea-bordered w-full"
                  rows={4}
                  value={editCallbackUrls}
                  onInput={e => setEditCallbackUrls((e.target as HTMLTextAreaElement).value)}
                  disabled={clientSubmitting}
                  placeholder="http://localhost:3000/callback"
                />
              </fieldset>
              <div class="modal-action mt-6">
                <button type="button" class="btn btn-ghost" onClick={() => setShowEditClientModal(false)} disabled={clientSubmitting}>Cancel</button>
                <button type="submit" class="btn" disabled={clientSubmitting}>
                  {clientSubmitting ? 'Saving...' : 'Save'}
                </button>
              </div>
            </form>
          </div>
          <form method="dialog" class="modal-backdrop"><button onClick={() => setShowEditClientModal(false)}>close</button></form>
        </dialog>
      )}
    </>
  )
}

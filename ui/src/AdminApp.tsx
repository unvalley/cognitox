import { useState } from 'preact/hooks'
import type { AdminPage, UserPool, User, UserPoolClient } from './lib/types'
import { Dashboard } from './admin/Dashboard'
import { UserPoolList } from './admin/UserPoolList'
import { UserPoolDetail } from './admin/UserPoolDetail'
import { UserList } from './admin/UserList'
import { UserDetail } from './admin/UserDetail'
import { ClientList } from './admin/ClientList'
import { ClientDetail } from './admin/ClientDetail'
import { BrandingEditor } from './admin/BrandingEditor'

export function AdminApp() {
  const [page, setPage] = useState<AdminPage>('dashboard')
  const [selectedUserPool, setSelectedUserPool] = useState<UserPool | null>(null)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [selectedClient, setSelectedClient] = useState<UserPoolClient | null>(null)

  function navigate(newPage: AdminPage, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) {
    setPage(newPage)
    if (context?.userPool !== undefined) setSelectedUserPool(context.userPool)
    if (context?.user !== undefined) setSelectedUser(context.user)
    if (context?.client !== undefined) setSelectedClient(context.client)
  }

  const navItems: { page: AdminPage; label: string; match: AdminPage[] }[] = [
    { page: 'dashboard', label: 'Dashboard', match: ['dashboard'] },
    { page: 'user-pools', label: 'User Pools', match: ['user-pools', 'user-pool-detail'] },
  ]

  const subNavItems: { page: AdminPage; label: string; match: AdminPage[] }[] = [
    { page: 'users', label: 'Users', match: ['users', 'user-detail'] },
    { page: 'clients', label: 'App Clients', match: ['clients', 'client-detail'] },
    { page: 'branding', label: 'Branding', match: ['branding'] },
  ]

  function renderContent() {
    switch (page) {
      case 'dashboard':
        return <Dashboard navigate={navigate} />
      case 'user-pools':
        return <UserPoolList navigate={navigate} />
      case 'user-pool-detail':
        return selectedUserPool ? <UserPoolDetail userPool={selectedUserPool} navigate={navigate} /> : null
      case 'users':
        return selectedUserPool ? <UserList userPool={selectedUserPool} navigate={navigate} /> : null
      case 'user-detail':
        return selectedUserPool && selectedUser ? <UserDetail userPool={selectedUserPool} user={selectedUser} navigate={navigate} /> : null
      case 'clients':
        return selectedUserPool ? <ClientList userPool={selectedUserPool} navigate={navigate} /> : null
      case 'client-detail':
        return selectedUserPool && selectedClient ? <ClientDetail userPool={selectedUserPool} client={selectedClient} navigate={navigate} /> : null
      case 'branding':
        return selectedUserPool ? <BrandingEditor userPool={selectedUserPool} navigate={navigate} /> : null
      default:
        return <div class="flex items-center justify-center h-96 text-base-content/50">Select an item from the sidebar to get started.</div>
    }
  }

  return (
    <div class="flex min-h-screen">
      <aside class="w-64 bg-base-300 text-base-content flex flex-col fixed h-screen overflow-y-auto">
        <div class="p-6 border-b border-base-content/10">
          <h1 class="text-2xl font-bold text-primary">Cognitox</h1>
          <span class="text-xs text-base-content/60">Admin Console</span>
        </div>

        <nav class="flex-1 py-4">
          <ul class="menu menu-sm w-full">
            {navItems.map(item => (
              <li key={item.page}>
                <button
                  class={item.match.includes(page) ? 'active' : ''}
                  onClick={() => navigate(item.page)}
                >
                  {item.label}
                </button>
              </li>
            ))}
            {selectedUserPool && (
              <li>
                <details open>
                  <summary class="text-base-content/60 text-xs uppercase tracking-wider">{selectedUserPool.Name}</summary>
                  <ul>
                    {subNavItems.map(item => (
                      <li key={item.page}>
                        <button
                          class={item.match.includes(page) ? 'active' : ''}
                          onClick={() => navigate(item.page)}
                        >
                          {item.label}
                        </button>
                      </li>
                    ))}
                  </ul>
                </details>
              </li>
            )}
          </ul>
        </nav>

        <div class="p-4 border-t border-base-content/10">
          <a href="/ui/" class="btn btn-ghost btn-sm w-full">Hosted UI</a>
        </div>
      </aside>

      <main class="flex-1 ml-64 p-6 min-h-screen bg-base-200">
        {renderContent()}
      </main>
    </div>
  )
}

import { LocationProvider, Router, Route, useLocation } from 'preact-iso'
import type { UserPool, User, UserPoolClient } from './lib/types'
import { Dashboard } from './admin/Dashboard'
import { UserPoolList } from './admin/UserPoolList'
import { UserPoolDetail } from './admin/UserPoolDetail'
import { UserList } from './admin/UserList'
import { UserDetail } from './admin/UserDetail'
import { ClientList } from './admin/ClientList'
import { ClientDetail } from './admin/ClientDetail'
import { BrandingEditor } from './admin/BrandingEditor'
import { Docs } from './admin/Docs'
import { useState } from 'preact/hooks'

function AdminLayout() {
  const { path, route } = useLocation()
  const [selectedUserPool, setSelectedUserPool] = useState<UserPool | null>(null)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [selectedClient, setSelectedClient] = useState<UserPoolClient | null>(null)

  function navigate(urlPath: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) {
    if (context?.userPool !== undefined) setSelectedUserPool(context.userPool)
    if (context?.user !== undefined) setSelectedUser(context.user)
    if (context?.client !== undefined) setSelectedClient(context.client)
    route(urlPath)
  }

  function handleNavClick(targetPath: string) {
    // Close mobile drawer on navigation
    const toggle = document.getElementById('admin-drawer') as HTMLInputElement | null
    if (toggle) toggle.checked = false
    navigate(targetPath)
  }

  const sidebar = (
    <>
      <div class="p-6 border-b border-base-content/10">
        <h1 class="text-2xl font-bold text-primary">Cognitox</h1>
        <span class="text-xs text-base-content/60">Admin Console</span>
      </div>

      <ul class="menu w-full grow p-4">
        <li>
          <a
            class={path === '/admin/' || path === '/admin' ? 'active' : ''}
            onClick={() => handleNavClick('/admin/')}
          >
            Dashboard
          </a>
        </li>
        <li>
          <a
            class={path.startsWith('/admin/pools') ? 'active' : ''}
            onClick={() => handleNavClick('/admin/pools')}
          >
            User Pools
          </a>
        </li>
        <li>
          <a
            class={path.startsWith('/admin/docs') ? 'active' : ''}
            onClick={() => handleNavClick('/admin/docs')}
          >
            Docs
          </a>
        </li>
      </ul>

      <div class="p-4 border-t border-base-content/10 space-y-2">
        <button class="btn btn-ghost btn-sm w-full" onClick={() => { window.location.href = '/ui/' }}>Hosted UI</button>
        <button class="btn btn-ghost btn-sm w-full text-base-content/60" onClick={() => { window.location.href = '/ui/' }}>Logout</button>
      </div>
    </>
  )

  return (
    <div class="drawer lg:drawer-open">
      <input id="admin-drawer" type="checkbox" class="drawer-toggle" />

      <div class="drawer-content flex flex-col">
        {/* Mobile navbar */}
        <nav class="navbar bg-base-300 w-full lg:hidden">
          <label for="admin-drawer" aria-label="open sidebar" class="btn btn-square btn-ghost">
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" class="inline-block h-6 w-6 stroke-current">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </label>
          <div class="px-4 font-bold text-primary">Cognitox</div>
        </nav>

        {/* Main content */}
        <main class="p-6 min-h-screen bg-base-200">
          <Router>
            <Route path="/admin/" component={() => <Dashboard navigate={navigate} />} />
            <Route path="/admin/pools" component={() => <UserPoolList navigate={navigate} />} />
            <Route
              path="/admin/pools/:poolId"
              component={({ poolId }: { poolId: string }) => {
                if (selectedUserPool && selectedUserPool.Id === poolId) {
                  return <UserPoolDetail userPool={selectedUserPool} navigate={navigate} />
                }
                return <UserPoolList navigate={navigate} />
              }}
            />
            <Route
              path="/admin/pools/:poolId/users"
              component={() =>
                selectedUserPool ? <UserList userPool={selectedUserPool} navigate={navigate} /> : null
              }
            />
            <Route
              path="/admin/pools/:poolId/users/:username"
              component={() =>
                selectedUserPool && selectedUser
                  ? <UserDetail userPool={selectedUserPool} user={selectedUser} navigate={navigate} />
                  : null
              }
            />
            <Route
              path="/admin/pools/:poolId/clients"
              component={() =>
                selectedUserPool ? <ClientList userPool={selectedUserPool} navigate={navigate} /> : null
              }
            />
            <Route
              path="/admin/pools/:poolId/clients/:clientId"
              component={() =>
                selectedUserPool && selectedClient
                  ? <ClientDetail userPool={selectedUserPool} client={selectedClient} navigate={navigate} />
                  : null
              }
            />
            <Route
              path="/admin/pools/:poolId/branding"
              component={() =>
                selectedUserPool ? <BrandingEditor userPool={selectedUserPool} navigate={navigate} /> : null
              }
            />
            <Route path="/admin/docs" component={Docs} />
            <Route default component={() => <Dashboard navigate={navigate} />} />
          </Router>
        </main>
      </div>

      <div class="drawer-side">
        <label for="admin-drawer" aria-label="close sidebar" class="drawer-overlay" />
        <div class="bg-base-300 text-base-content min-h-full w-64 flex flex-col">
          {sidebar}
        </div>
      </div>
    </div>
  )
}

export function AdminApp() {
  return (
    <LocationProvider>
      <AdminLayout />
    </LocationProvider>
  )
}

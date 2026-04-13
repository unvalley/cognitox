import { Route, Router, useLocation } from 'preact-iso'
import { useState } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from './lib/types'
import { UserPoolList } from './admin/UserPoolList'
import { UserPoolDetail } from './admin/UserPoolDetail'
import { UserList } from './admin/UserList'
import { UserDetail } from './admin/UserDetail'
import { ClientList } from './admin/ClientList'
import { ClientDetail } from './admin/ClientDetail'
import { BrandingEditor } from './admin/BrandingEditor'

function AdminLayout() {
  const { route } = useLocation()
  const [selectedUserPool, setSelectedUserPool] = useState<UserPool | null>(null)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [selectedClient, setSelectedClient] = useState<UserPoolClient | null>(null)

  function navigate(urlPath: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) {
    if (context?.userPool !== undefined) setSelectedUserPool(context.userPool)
    if (context?.user !== undefined) setSelectedUser(context.user)
    if (context?.client !== undefined) setSelectedClient(context.client)
    route(urlPath)
  }

  return (
    <div class="admin-shell flex min-h-screen flex-col">
      <header class="bg-white">
        <div class="px-4 py-4 sm:px-6">
          <div class="mx-auto flex max-w-7xl items-center justify-between gap-3">
            <div class="flex items-center">
              <img src="/icon-192-rounded.png" alt="Cognitox" class="h-10 w-10 rounded-xl" />
            </div>

            <div class="flex items-center gap-5">
              <a
                class="text-sm text-slate-500 hover:text-slate-900"
                href="https://github.com/unvalley/cognitox"
                target="_blank"
                rel="noopener noreferrer"
              >
                Docs
              </a>
              <button class="btn btn-sm" onClick={() => { window.location.href = '/ui/' }}>Hosted UI</button>
            </div>
          </div>
        </div>
      </header>

      <main class="flex-1 bg-white px-4 py-4 sm:px-6 sm:py-6">
        <div class="mx-auto max-w-7xl">
          <Router>
            <Route path="/admin/" component={() => <UserPoolList />} />
            <Route path="/admin" component={() => <UserPoolList />} />
            <Route path="/admin/pools" component={() => <UserPoolList />} />
            <Route
              path="/admin/pools/:poolId"
              component={({ poolId }: { poolId: string }) => {
                if (selectedUserPool && selectedUserPool.Id === poolId) {
                  return <UserPoolDetail userPool={selectedUserPool} navigate={navigate} />
                }
                return <UserPoolList />
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
            <Route default component={() => <UserPoolList />} />
          </Router>
        </div>
      </main>

      <footer class="px-4 pb-4 pt-2 sm:px-6 sm:pb-6">
        <div class="mx-auto max-w-7xl text-center text-sm text-slate-500">
          <a
            class="btn btn-link btn-sm px-0 text-slate-500 no-underline hover:no-underline"
            href="https://github.com/unvalley/cognitox"
            target="_blank"
            rel="noopener noreferrer"
          >
            github.com/unvalley/cognitox
          </a>
        </div>
      </footer>
    </div>
  )
}

export function AdminApp() {
  return <AdminLayout />
}

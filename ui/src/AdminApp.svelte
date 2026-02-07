<script lang="ts">
  import type { AdminPage, UserPool, User, UserPoolClient } from './lib/types'
  import Dashboard from './admin/Dashboard.svelte'
  import UserPoolList from './admin/UserPoolList.svelte'
  import UserPoolDetail from './admin/UserPoolDetail.svelte'
  import UserList from './admin/UserList.svelte'
  import UserDetail from './admin/UserDetail.svelte'
  import ClientList from './admin/ClientList.svelte'
  import ClientDetail from './admin/ClientDetail.svelte'
  import BrandingEditor from './admin/BrandingEditor.svelte'

  let page: AdminPage = $state('dashboard')
  let selectedUserPool: UserPool | null = $state(null)
  let selectedUser: User | null = $state(null)
  let selectedClient: UserPoolClient | null = $state(null)

  function navigate(newPage: AdminPage, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) {
    page = newPage
    if (context?.userPool !== undefined) selectedUserPool = context.userPool
    if (context?.user !== undefined) selectedUser = context.user
    if (context?.client !== undefined) selectedClient = context.client
  }
</script>

<div class="admin-layout">
  <aside class="sidebar">
    <div class="logo">
      <h1>Cognitox</h1>
      <span class="subtitle">Admin Console</span>
    </div>

    <nav>
      <button
        class="nav-item"
        class:active={page === 'dashboard'}
        onclick={() => navigate('dashboard')}
      >
        Dashboard
      </button>
      <button
        class="nav-item"
        class:active={page === 'user-pools' || page === 'user-pool-detail'}
        onclick={() => navigate('user-pools')}
      >
        User Pools
      </button>
      {#if selectedUserPool}
        <div class="nav-sub">
          <button
            class="nav-item sub"
            class:active={page === 'users' || page === 'user-detail'}
            onclick={() => navigate('users')}
          >
            Users
          </button>
          <button
            class="nav-item sub"
            class:active={page === 'clients' || page === 'client-detail'}
            onclick={() => navigate('clients')}
          >
            App Clients
          </button>
          <button
            class="nav-item sub"
            class:active={page === 'branding'}
            onclick={() => navigate('branding')}
          >
            Branding
          </button>
        </div>
      {/if}
    </nav>

    <div class="sidebar-footer">
      <a href="/ui/" class="nav-item">Hosted UI</a>
    </div>
  </aside>

  <main class="content">
    {#if page === 'dashboard'}
      <Dashboard {navigate} />
    {:else if page === 'user-pools'}
      <UserPoolList {navigate} />
    {:else if page === 'user-pool-detail' && selectedUserPool}
      <UserPoolDetail userPool={selectedUserPool} {navigate} />
    {:else if page === 'users' && selectedUserPool}
      <UserList userPool={selectedUserPool} {navigate} />
    {:else if page === 'user-detail' && selectedUserPool && selectedUser}
      <UserDetail userPool={selectedUserPool} user={selectedUser} {navigate} />
    {:else if page === 'clients' && selectedUserPool}
      <ClientList userPool={selectedUserPool} {navigate} />
    {:else if page === 'client-detail' && selectedUserPool && selectedClient}
      <ClientDetail userPool={selectedUserPool} client={selectedClient} {navigate} />
    {:else if page === 'branding' && selectedUserPool}
      <BrandingEditor userPool={selectedUserPool} {navigate} />
    {:else}
      <div class="empty-state">
        <p>Select an item from the sidebar to get started.</p>
      </div>
    {/if}
  </main>
</div>

<style>
  .admin-layout {
    display: flex;
    min-height: 100vh;
    background-color: #f8f9fa;
  }

  .sidebar {
    width: 250px;
    background-color: #1a1a2e;
    color: white;
    display: flex;
    flex-direction: column;
    position: fixed;
    height: 100vh;
    overflow-y: auto;
  }

  .logo {
    padding: 24px 20px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  }

  .logo h1 {
    font-size: 24px;
    font-weight: 700;
    margin: 0;
    color: #4fc3f7;
  }

  .logo .subtitle {
    font-size: 12px;
    color: rgba(255, 255, 255, 0.6);
  }

  nav {
    flex: 1;
    padding: 16px 0;
  }

  .nav-item {
    display: block;
    width: 100%;
    padding: 12px 20px;
    border: none;
    background: none;
    color: rgba(255, 255, 255, 0.8);
    text-align: left;
    font-size: 14px;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
  }

  .nav-item:hover {
    background-color: rgba(255, 255, 255, 0.1);
    color: white;
  }

  .nav-item.active {
    background-color: rgba(79, 195, 247, 0.2);
    color: #4fc3f7;
    border-left: 3px solid #4fc3f7;
  }

  .nav-sub {
    background-color: rgba(0, 0, 0, 0.2);
  }

  .nav-item.sub {
    padding-left: 36px;
    font-size: 13px;
  }

  .sidebar-footer {
    padding: 16px 0;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
  }

  .content {
    flex: 1;
    margin-left: 250px;
    padding: 24px;
    min-height: 100vh;
  }

  .empty-state {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 400px;
    color: #666;
  }
</style>

<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool, User, UserPoolClient } from '../lib/types'
  import { describeUserPool, listUsers, listUserPoolClients } from '../lib/api'

  interface Props {
    userPool: UserPool
    navigate: (page: AdminPage, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
  }

  let { userPool, navigate }: Props = $props()

  let pool: UserPool | null = $state(null)
  let users: User[] = $state([])
  let clients: UserPoolClient[] = $state([])
  let loading = $state(true)
  let error: string | null = $state(null)

  async function loadDetails() {
    try {
      loading = true
      const [poolData, usersData, clientsData] = await Promise.all([
        describeUserPool(userPool.Id),
        listUsers(userPool.Id),
        listUserPoolClients(userPool.Id),
      ])
      pool = poolData
      users = usersData
      clients = clientsData
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load user pool details'
    } finally {
      loading = false
    }
  }

  onMount(loadDetails)
</script>

<div class="page">
  <header class="page-header">
    <div class="breadcrumb">
      <button class="link-btn" onclick={() => navigate('user-pools')}>User Pools</button>
      <span>/</span>
      <span>{userPool.Name}</span>
    </div>
    <h1>{userPool.Name}</h1>
    <p class="pool-id"><code>{userPool.Id}</code></p>
  </header>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if pool}
    <div class="details-grid">
      <section class="detail-card">
        <h2>Pool Information</h2>
        <dl>
          <div class="detail-row">
            <dt>Pool ID</dt>
            <dd><code>{pool.Id}</code></dd>
          </div>
          <div class="detail-row">
            <dt>Name</dt>
            <dd>{pool.Name}</dd>
          </div>
          <div class="detail-row">
            <dt>Created</dt>
            <dd>{new Date(pool.CreationDate).toLocaleString()}</dd>
          </div>
          <div class="detail-row">
            <dt>Last Modified</dt>
            <dd>{new Date(pool.LastModifiedDate).toLocaleString()}</dd>
          </div>
          {#if pool.Domain}
            <div class="detail-row">
              <dt>Domain</dt>
              <dd>{pool.Domain}</dd>
            </div>
          {/if}
        </dl>
      </section>

      <section class="detail-card">
        <div class="card-header">
          <h2>Users ({users.length})</h2>
          <button class="btn btn-sm" onclick={() => navigate('users', { userPool })}>
            Manage
          </button>
        </div>
        {#if users.length === 0}
          <p class="empty-text">No users yet</p>
        {:else}
          <ul class="item-list">
            {#each users.slice(0, 5) as user}
              <li>
                <button
                  class="link-btn"
                  onclick={() => navigate('user-detail', { userPool, user })}
                >
                  {user.Username}
                </button>
                <span class="badge" class:confirmed={user.UserStatus === 'CONFIRMED'}>
                  {user.UserStatus}
                </span>
              </li>
            {/each}
          </ul>
          {#if users.length > 5}
            <button class="btn-link" onclick={() => navigate('users', { userPool })}>
              View all {users.length} users
            </button>
          {/if}
        {/if}
      </section>

      <section class="detail-card">
        <div class="card-header">
          <h2>App Clients ({clients.length})</h2>
          <button class="btn btn-sm" onclick={() => navigate('clients', { userPool })}>
            Manage
          </button>
        </div>
        {#if clients.length === 0}
          <p class="empty-text">No app clients yet</p>
        {:else}
          <ul class="item-list">
            {#each clients.slice(0, 5) as client}
              <li>
                <button
                  class="link-btn"
                  onclick={() => navigate('client-detail', { userPool, client })}
                >
                  {client.ClientName}
                </button>
                <code class="small">{client.ClientId}</code>
              </li>
            {/each}
          </ul>
          {#if clients.length > 5}
            <button class="btn-link" onclick={() => navigate('clients', { userPool })}>
              View all {clients.length} clients
            </button>
          {/if}
        {/if}
      </section>

      <section class="detail-card">
        <div class="card-header">
          <h2>Branding</h2>
          <button class="btn btn-sm" onclick={() => navigate('branding', { userPool })}>
            Configure
          </button>
        </div>
        <p class="empty-text">Customize the hosted UI appearance</p>
      </section>
    </div>
  {/if}
</div>

<style>
  .page {
    max-width: 1200px;
  }

  .page-header {
    margin-bottom: 32px;
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    color: #666;
    margin-bottom: 8px;
  }

  .breadcrumb span {
    color: #999;
  }

  .page-header h1 {
    font-size: 28px;
    font-weight: 600;
    margin: 0 0 8px 0;
    color: #1a1a2e;
  }

  .pool-id code {
    background: #f5f5f5;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 14px;
  }

  .error-banner {
    background-color: #fee;
    border: 1px solid #fcc;
    color: #c00;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
  }

  .loading {
    text-align: center;
    padding: 40px;
    color: #666;
  }

  .details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 24px;
  }

  .detail-card {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }

  .detail-card h2 {
    font-size: 18px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
  }

  .card-header h2 {
    margin: 0;
  }

  dl {
    margin: 0;
  }

  .detail-row {
    display: flex;
    padding: 12px 0;
    border-bottom: 1px solid #eee;
  }

  .detail-row:last-child {
    border-bottom: none;
  }

  dt {
    font-weight: 500;
    color: #666;
    width: 140px;
    flex-shrink: 0;
  }

  dd {
    margin: 0;
    color: #333;
  }

  dd code {
    background: #f5f5f5;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 13px;
  }

  .item-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .item-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid #eee;
  }

  .item-list li:last-child {
    border-bottom: none;
  }

  .badge {
    font-size: 11px;
    padding: 4px 8px;
    border-radius: 4px;
    background-color: #f5f5f5;
    color: #666;
    text-transform: uppercase;
  }

  .badge.confirmed {
    background-color: #e8f5e9;
    color: #2e7d32;
  }

  code.small {
    font-size: 11px;
    background: #f5f5f5;
    padding: 2px 6px;
    border-radius: 4px;
  }

  .empty-text {
    color: #666;
    font-size: 14px;
    margin: 0;
  }

  .link-btn {
    background: none;
    border: none;
    color: #4fc3f7;
    cursor: pointer;
    font-size: inherit;
    font-weight: 500;
    padding: 0;
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .btn {
    padding: 10px 20px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-sm {
    padding: 6px 12px;
    font-size: 13px;
    background-color: #f0f0f0;
    color: #333;
  }

  .btn-sm:hover {
    background-color: #e0e0e0;
  }

  .btn-link {
    background: none;
    border: none;
    color: #4fc3f7;
    cursor: pointer;
    font-size: 14px;
    padding: 8px 0;
    margin-top: 8px;
  }

  .btn-link:hover {
    text-decoration: underline;
  }
</style>

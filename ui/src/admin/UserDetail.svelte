<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool, User } from '../lib/types'
  import { adminGetUser, adminDeleteUser, adminEnableUser, adminDisableUser } from '../lib/api'

  interface Props {
    userPool: UserPool
    user: User
    navigate: (page: AdminPage, context?: { userPool?: UserPool; user?: User }) => void
  }

  let { userPool, user: initialUser, navigate }: Props = $props()

  let user: User | null = $state(null)
  let loading = $state(true)
  let error: string | null = $state(null)

  async function loadUser() {
    try {
      loading = true
      user = await adminGetUser(userPool.Id, initialUser.Username)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load user'
    } finally {
      loading = false
    }
  }

  async function handleDelete() {
    if (!user) return
    if (!confirm(`Are you sure you want to delete "${user.Username}"?`)) return

    try {
      await adminDeleteUser(userPool.Id, user.Username)
      navigate('users', { userPool })
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to delete user'
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
      user = { ...user, Enabled: !user.Enabled }
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to update user'
    }
  }

  onMount(loadUser)
</script>

<div class="page">
  <header class="page-header">
    <div class="breadcrumb">
      <button class="link-btn" onclick={() => navigate('user-pools')}>User Pools</button>
      <span>/</span>
      <button class="link-btn" onclick={() => navigate('user-pool-detail', { userPool })}>{userPool.Name}</button>
      <span>/</span>
      <button class="link-btn" onclick={() => navigate('users', { userPool })}>Users</button>
      <span>/</span>
      <span>{initialUser.Username}</span>
    </div>
    <div class="header-row">
      <h1>{initialUser.Username}</h1>
      <div class="header-actions">
        <button class="btn btn-secondary" onclick={handleToggleEnabled}>
          {user?.Enabled ? 'Disable User' : 'Enable User'}
        </button>
        <button class="btn btn-danger" onclick={handleDelete}>
          Delete User
        </button>
      </div>
    </div>
  </header>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if user}
    <div class="details-grid">
      <section class="detail-card">
        <h2>User Information</h2>
        <dl>
          <div class="detail-row">
            <dt>Username</dt>
            <dd>{user.Username}</dd>
          </div>
          <div class="detail-row">
            <dt>Status</dt>
            <dd>
              <span class="badge" class:confirmed={user.UserStatus === 'CONFIRMED'}>
                {user.UserStatus}
              </span>
            </dd>
          </div>
          <div class="detail-row">
            <dt>Enabled</dt>
            <dd>
              <span class="badge" class:enabled={user.Enabled}>
                {user.Enabled ? 'Yes' : 'No'}
              </span>
            </dd>
          </div>
          <div class="detail-row">
            <dt>Created</dt>
            <dd>{new Date(user.UserCreateDate).toLocaleString()}</dd>
          </div>
          <div class="detail-row">
            <dt>Last Modified</dt>
            <dd>{new Date(user.UserLastModifiedDate).toLocaleString()}</dd>
          </div>
        </dl>
      </section>

      <section class="detail-card">
        <h2>Attributes</h2>
        {#if user.Attributes && user.Attributes.length > 0}
          <dl>
            {#each user.Attributes as attr}
              <div class="detail-row">
                <dt>{attr.Name}</dt>
                <dd>{attr.Value}</dd>
              </div>
            {/each}
          </dl>
        {:else}
          <p class="empty-text">No attributes</p>
        {/if}
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
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  .breadcrumb span {
    color: #999;
  }

  .header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }

  .page-header h1 {
    font-size: 28px;
    font-weight: 600;
    margin: 0;
    color: #1a1a2e;
  }

  .header-actions {
    display: flex;
    gap: 12px;
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

  .detail-card h2 {
    font-size: 18px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
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
    word-break: break-all;
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

  .badge.enabled {
    background-color: #e8f5e9;
    color: #2e7d32;
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

  .btn-secondary {
    background-color: #e0e0e0;
    color: #333;
  }

  .btn-secondary:hover {
    background-color: #d0d0d0;
  }

  .btn-danger {
    background-color: #ffebee;
    color: #c62828;
  }

  .btn-danger:hover {
    background-color: #ffcdd2;
  }
</style>

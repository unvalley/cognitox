<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool } from '../lib/types'
  import { listUserPools } from '../lib/api'

  interface Props {
    navigate: (page: AdminPage, context?: { userPool?: UserPool }) => void
  }

  let { navigate }: Props = $props()

  let userPools: UserPool[] = $state([])
  let totalUsers = $state(0)
  let totalClients = $state(0)
  let loading = $state(true)
  let error: string | null = $state(null)

  onMount(async () => {
    try {
      userPools = await listUserPools()
      totalUsers = userPools.length * 0 // We'd need to aggregate, placeholder for now
      totalClients = userPools.length * 0
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load data'
    } finally {
      loading = false
    }
  })
</script>

<div class="dashboard">
  <header class="page-header">
    <h1>Dashboard</h1>
    <p>Overview of your Cognito emulator</p>
  </header>

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if error}
    <div class="error-banner">{error}</div>
  {:else}
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{userPools.length}</div>
        <div class="stat-label">User Pools</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{totalUsers}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{totalClients}</div>
        <div class="stat-label">App Clients</div>
      </div>
    </div>

    <section class="recent-section">
      <h2>User Pools</h2>
      {#if userPools.length === 0}
        <div class="empty-state">
          <p>No user pools yet.</p>
          <button class="btn btn-primary" onclick={() => navigate('user-pools')}>
            Create User Pool
          </button>
        </div>
      {:else}
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>ID</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each userPools.slice(0, 5) as pool}
                <tr>
                  <td>{pool.Name}</td>
                  <td><code>{pool.Id}</code></td>
                  <td>{new Date(pool.CreationDate).toLocaleDateString()}</td>
                  <td>
                    <button
                      class="btn btn-sm"
                      onclick={() => navigate('user-pool-detail', { userPool: pool })}
                    >
                      View
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        {#if userPools.length > 5}
          <button class="btn btn-link" onclick={() => navigate('user-pools')}>
            View all {userPools.length} user pools
          </button>
        {/if}
      {/if}
    </section>

    <section class="quick-actions">
      <h2>Quick Actions</h2>
      <div class="action-buttons">
        <button class="btn btn-primary" onclick={() => navigate('user-pools')}>
          Manage User Pools
        </button>
      </div>
    </section>
  {/if}
</div>

<style>
  .dashboard {
    max-width: 1200px;
  }

  .page-header {
    margin-bottom: 32px;
  }

  .page-header h1 {
    font-size: 28px;
    font-weight: 600;
    margin: 0 0 8px 0;
    color: #1a1a2e;
  }

  .page-header p {
    color: #666;
    margin: 0;
  }

  .loading {
    text-align: center;
    padding: 40px;
    color: #666;
  }

  .error-banner {
    background-color: #fee;
    border: 1px solid #fcc;
    color: #c00;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 24px;
    margin-bottom: 40px;
  }

  .stat-card {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .stat-value {
    font-size: 36px;
    font-weight: 700;
    color: #4fc3f7;
  }

  .stat-label {
    font-size: 14px;
    color: #666;
    margin-top: 4px;
  }

  .recent-section {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    margin-bottom: 24px;
  }

  .recent-section h2 {
    font-size: 18px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
  }

  .table-container {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #eee;
  }

  th {
    font-weight: 600;
    color: #666;
    font-size: 13px;
    text-transform: uppercase;
  }

  td code {
    background: #f5f5f5;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
  }

  .empty-state {
    text-align: center;
    padding: 40px;
    color: #666;
  }

  .quick-actions {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .quick-actions h2 {
    font-size: 18px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
  }

  .action-buttons {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
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

  .btn-primary {
    background-color: #4fc3f7;
    color: white;
  }

  .btn-primary:hover {
    background-color: #29b6f6;
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
    color: #4fc3f7;
    padding: 8px 0;
    margin-top: 12px;
  }

  .btn-link:hover {
    text-decoration: underline;
  }
</style>

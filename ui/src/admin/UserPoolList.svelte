<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool } from '../lib/types'
  import { listUserPools, createUserPool, deleteUserPool } from '../lib/api'

  interface Props {
    navigate: (page: AdminPage, context?: { userPool?: UserPool }) => void
  }

  let { navigate }: Props = $props()

  let userPools: UserPool[] = $state([])
  let loading = $state(true)
  let error: string | null = $state(null)
  let showCreateModal = $state(false)
  let newPoolName = $state('')
  let creating = $state(false)

  async function loadUserPools() {
    try {
      loading = true
      userPools = await listUserPools()
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load user pools'
    } finally {
      loading = false
    }
  }

  async function handleCreate() {
    if (!newPoolName.trim()) return

    try {
      creating = true
      const pool = await createUserPool(newPoolName.trim())
      userPools = [...userPools, pool]
      showCreateModal = false
      newPoolName = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to create user pool'
    } finally {
      creating = false
    }
  }

  async function handleDelete(pool: UserPool) {
    if (!confirm(`Are you sure you want to delete "${pool.Name}"?`)) return

    try {
      await deleteUserPool(pool.Id)
      userPools = userPools.filter(p => p.Id !== pool.Id)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to delete user pool'
    }
  }

  onMount(loadUserPools)
</script>

<div class="page">
  <header class="page-header">
    <div>
      <h1>User Pools</h1>
      <p>Manage your Cognito user pools</p>
    </div>
    <button class="btn btn-primary" onclick={() => (showCreateModal = true)}>
      Create User Pool
    </button>
  </header>

  {#if error}
    <div class="error-banner">
      {error}
      <button class="btn-close" onclick={() => (error = null)}>Dismiss</button>
    </div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if userPools.length === 0}
    <div class="empty-state">
      <h2>No User Pools</h2>
      <p>Create your first user pool to get started.</p>
      <button class="btn btn-primary" onclick={() => (showCreateModal = true)}>
        Create User Pool
      </button>
    </div>
  {:else}
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Pool ID</th>
            <th>Created</th>
            <th>Modified</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each userPools as pool}
            <tr>
              <td>
                <button
                  class="link-btn"
                  onclick={() => navigate('user-pool-detail', { userPool: pool })}
                >
                  {pool.Name}
                </button>
              </td>
              <td><code>{pool.Id}</code></td>
              <td>{new Date(pool.CreationDate).toLocaleString()}</td>
              <td>{new Date(pool.LastModifiedDate).toLocaleString()}</td>
              <td>
                <div class="action-btns">
                  <button
                    class="btn btn-sm"
                    onclick={() => navigate('user-pool-detail', { userPool: pool })}
                  >
                    View
                  </button>
                  <button
                    class="btn btn-sm btn-danger"
                    onclick={() => handleDelete(pool)}
                  >
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if showCreateModal}
  <div class="modal-overlay" onclick={() => (showCreateModal = false)}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h2>Create User Pool</h2>
      <form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
        <div class="form-group">
          <label for="poolName">Pool Name</label>
          <input
            type="text"
            id="poolName"
            bind:value={newPoolName}
            placeholder="my-user-pool"
            disabled={creating}
            required
          />
        </div>
        <div class="modal-actions">
          <button
            type="button"
            class="btn btn-secondary"
            onclick={() => (showCreateModal = false)}
            disabled={creating}
          >
            Cancel
          </button>
          <button type="submit" class="btn btn-primary" disabled={creating}>
            {creating ? 'Creating...' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  .page {
    max-width: 1200px;
  }

  .page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
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

  .error-banner {
    background-color: #fee;
    border: 1px solid #fcc;
    color: #c00;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .btn-close {
    background: none;
    border: none;
    color: #c00;
    cursor: pointer;
    font-size: 14px;
  }

  .loading {
    text-align: center;
    padding: 40px;
    color: #666;
  }

  .empty-state {
    background: white;
    padding: 60px;
    border-radius: 12px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .empty-state h2 {
    font-size: 20px;
    margin: 0 0 8px 0;
    color: #1a1a2e;
  }

  .empty-state p {
    color: #666;
    margin: 0 0 24px 0;
  }

  .table-container {
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th, td {
    padding: 16px;
    text-align: left;
    border-bottom: 1px solid #eee;
  }

  th {
    font-weight: 600;
    color: #666;
    font-size: 13px;
    text-transform: uppercase;
    background-color: #fafafa;
  }

  td code {
    background: #f5f5f5;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
  }

  .link-btn {
    background: none;
    border: none;
    color: #4fc3f7;
    cursor: pointer;
    font-size: inherit;
    font-weight: 500;
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .action-btns {
    display: flex;
    gap: 8px;
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

  .btn-secondary {
    background-color: #e0e0e0;
    color: #333;
  }

  .btn-secondary:hover {
    background-color: #d0d0d0;
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

  .btn-danger {
    background-color: #ffebee;
    color: #c62828;
  }

  .btn-danger:hover {
    background-color: #ffcdd2;
  }

  .btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  /* Modal */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .modal {
    background: white;
    padding: 32px;
    border-radius: 12px;
    width: 100%;
    max-width: 400px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
  }

  .modal h2 {
    font-size: 20px;
    margin: 0 0 24px 0;
    color: #1a1a2e;
  }

  .form-group {
    margin-bottom: 20px;
  }

  .form-group label {
    display: block;
    margin-bottom: 8px;
    font-size: 14px;
    font-weight: 500;
    color: #333;
  }

  .form-group input {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
  }

  .form-group input:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
  }
</style>

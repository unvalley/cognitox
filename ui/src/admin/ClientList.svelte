<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool, UserPoolClient } from '../lib/types'
  import { listUserPoolClients, createUserPoolClient, deleteUserPoolClient } from '../lib/api'

  interface Props {
    userPool: UserPool
    navigate: (page: AdminPage, context?: { userPool?: UserPool; client?: UserPoolClient }) => void
  }

  let { userPool, navigate }: Props = $props()

  let clients: UserPoolClient[] = $state([])
  let loading = $state(true)
  let error: string | null = $state(null)
  let showCreateModal = $state(false)
  let newClientName = $state('')
  let newCallbackUrls = $state('')
  let creating = $state(false)

  async function loadClients() {
    try {
      loading = true
      clients = await listUserPoolClients(userPool.Id)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load clients'
    } finally {
      loading = false
    }
  }

  async function handleCreate() {
    if (!newClientName.trim()) return

    try {
      creating = true
      const callbackUrls = newCallbackUrls
        .split('\n')
        .map(url => url.trim())
        .filter(url => url.length > 0)

      const client = await createUserPoolClient(
        userPool.Id,
        newClientName.trim(),
        callbackUrls.length > 0 ? callbackUrls : undefined,
        ['code'],
        ['openid', 'email', 'profile']
      )
      clients = [...clients, client]
      showCreateModal = false
      newClientName = ''
      newCallbackUrls = ''
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to create client'
    } finally {
      creating = false
    }
  }

  async function handleDelete(client: UserPoolClient) {
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return

    try {
      await deleteUserPoolClient(userPool.Id, client.ClientId)
      clients = clients.filter(c => c.ClientId !== client.ClientId)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to delete client'
    }
  }

  onMount(loadClients)
</script>

<div class="page">
  <header class="page-header">
    <div class="breadcrumb">
      <button class="link-btn" onclick={() => navigate('user-pools')}>User Pools</button>
      <span>/</span>
      <button class="link-btn" onclick={() => navigate('user-pool-detail', { userPool })}>{userPool.Name}</button>
      <span>/</span>
      <span>App Clients</span>
    </div>
    <div class="header-row">
      <h1>App Clients</h1>
      <button class="btn btn-primary" onclick={() => (showCreateModal = true)}>
        Create Client
      </button>
    </div>
  </header>

  {#if error}
    <div class="error-banner">
      {error}
      <button class="btn-close" onclick={() => (error = null)}>Dismiss</button>
    </div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if clients.length === 0}
    <div class="empty-state">
      <h2>No App Clients</h2>
      <p>Create your first app client for this pool.</p>
      <button class="btn btn-primary" onclick={() => (showCreateModal = true)}>
        Create Client
      </button>
    </div>
  {:else}
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Client ID</th>
            <th>OAuth Flows</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each clients as client}
            <tr>
              <td>
                <button
                  class="link-btn"
                  onclick={() => navigate('client-detail', { userPool, client })}
                >
                  {client.ClientName}
                </button>
              </td>
              <td><code>{client.ClientId}</code></td>
              <td>
                {#if client.AllowedOAuthFlows && client.AllowedOAuthFlows.length > 0}
                  {client.AllowedOAuthFlows.join(', ')}
                {:else}
                  -
                {/if}
              </td>
              <td>
                <div class="action-btns">
                  <button
                    class="btn btn-sm"
                    onclick={() => navigate('client-detail', { userPool, client })}
                  >
                    View
                  </button>
                  <button
                    class="btn btn-sm btn-danger"
                    onclick={() => handleDelete(client)}
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
      <h2>Create App Client</h2>
      <form onsubmit={(e) => { e.preventDefault(); handleCreate(); }}>
        <div class="form-group">
          <label for="clientName">Client Name</label>
          <input
            type="text"
            id="clientName"
            bind:value={newClientName}
            placeholder="my-web-app"
            disabled={creating}
            required
          />
        </div>
        <div class="form-group">
          <label for="callbackUrls">Callback URLs (one per line)</label>
          <textarea
            id="callbackUrls"
            bind:value={newCallbackUrls}
            placeholder="http://localhost:3000/callback"
            disabled={creating}
            rows="3"
          ></textarea>
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
    margin-bottom: 32px;
  }

  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    color: #666;
    margin-bottom: 16px;
  }

  .breadcrumb span {
    color: #999;
  }

  .header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .page-header h1 {
    font-size: 28px;
    font-weight: 600;
    margin: 0;
    color: #1a1a2e;
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
    padding: 0;
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
    max-width: 450px;
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

  .form-group input,
  .form-group textarea {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
    font-family: inherit;
  }

  .form-group input:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
  }
</style>

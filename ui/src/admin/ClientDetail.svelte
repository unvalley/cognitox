<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool, UserPoolClient } from '../lib/types'
  import { describeUserPoolClient, deleteUserPoolClient } from '../lib/api'

  interface Props {
    userPool: UserPool
    client: UserPoolClient
    navigate: (page: AdminPage, context?: { userPool?: UserPool; client?: UserPoolClient }) => void
  }

  let { userPool, client: initialClient, navigate }: Props = $props()

  let client: UserPoolClient | null = $state(null)
  let loading = $state(true)
  let error: string | null = $state(null)
  let copied = $state(false)

  async function loadClient() {
    try {
      loading = true
      client = await describeUserPoolClient(userPool.Id, initialClient.ClientId)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load client'
    } finally {
      loading = false
    }
  }

  async function handleDelete() {
    if (!client) return
    if (!confirm(`Are you sure you want to delete "${client.ClientName}"?`)) return

    try {
      await deleteUserPoolClient(userPool.Id, client.ClientId)
      navigate('clients', { userPool })
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to delete client'
    }
  }

  async function copyClientId() {
    if (!client) return
    await navigator.clipboard.writeText(client.ClientId)
    copied = true
    setTimeout(() => (copied = false), 2000)
  }

  function getHostedUIUrl(): string {
    if (!client) return ''
    const callbackUrl = client.CallbackURLs?.[0] || 'http://localhost:3000/callback'
    return `http://localhost:9229/ui/?response_type=code&client_id=${client.ClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
  }

  onMount(loadClient)
</script>

<div class="page">
  <header class="page-header">
    <div class="breadcrumb">
      <button class="link-btn" onclick={() => navigate('user-pools')}>User Pools</button>
      <span>/</span>
      <button class="link-btn" onclick={() => navigate('user-pool-detail', { userPool })}>{userPool.Name}</button>
      <span>/</span>
      <button class="link-btn" onclick={() => navigate('clients', { userPool })}>App Clients</button>
      <span>/</span>
      <span>{initialClient.ClientName}</span>
    </div>
    <div class="header-row">
      <h1>{initialClient.ClientName}</h1>
      <button class="btn btn-danger" onclick={handleDelete}>
        Delete Client
      </button>
    </div>
  </header>

  {#if error}
    <div class="error-banner">{error}</div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if client}
    <div class="details-grid">
      <section class="detail-card">
        <h2>Client Information</h2>
        <dl>
          <div class="detail-row">
            <dt>Client Name</dt>
            <dd>{client.ClientName}</dd>
          </div>
          <div class="detail-row">
            <dt>Client ID</dt>
            <dd class="client-id-row">
              <code>{client.ClientId}</code>
              <button class="btn btn-sm" onclick={copyClientId}>
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </dd>
          </div>
          <div class="detail-row">
            <dt>User Pool ID</dt>
            <dd><code>{client.UserPoolId}</code></dd>
          </div>
        </dl>
      </section>

      <section class="detail-card">
        <h2>OAuth 2.0 Settings</h2>
        <dl>
          <div class="detail-row">
            <dt>Allowed OAuth Flows</dt>
            <dd>
              {#if client.AllowedOAuthFlows && client.AllowedOAuthFlows.length > 0}
                <div class="tags">
                  {#each client.AllowedOAuthFlows as flow}
                    <span class="tag">{flow}</span>
                  {/each}
                </div>
              {:else}
                <span class="empty-text">None configured</span>
              {/if}
            </dd>
          </div>
          <div class="detail-row">
            <dt>Allowed OAuth Scopes</dt>
            <dd>
              {#if client.AllowedOAuthScopes && client.AllowedOAuthScopes.length > 0}
                <div class="tags">
                  {#each client.AllowedOAuthScopes as scope}
                    <span class="tag">{scope}</span>
                  {/each}
                </div>
              {:else}
                <span class="empty-text">None configured</span>
              {/if}
            </dd>
          </div>
          <div class="detail-row">
            <dt>Explicit Auth Flows</dt>
            <dd>
              {#if client.ExplicitAuthFlows && client.ExplicitAuthFlows.length > 0}
                <div class="tags">
                  {#each client.ExplicitAuthFlows as flow}
                    <span class="tag">{flow}</span>
                  {/each}
                </div>
              {:else}
                <span class="empty-text">None configured</span>
              {/if}
            </dd>
          </div>
        </dl>
      </section>

      <section class="detail-card">
        <h2>Callback URLs</h2>
        {#if client.CallbackURLs && client.CallbackURLs.length > 0}
          <ul class="url-list">
            {#each client.CallbackURLs as url}
              <li><code>{url}</code></li>
            {/each}
          </ul>
        {:else}
          <p class="empty-text">No callback URLs configured</p>
        {/if}
      </section>

      <section class="detail-card">
        <h2>Logout URLs</h2>
        {#if client.LogoutURLs && client.LogoutURLs.length > 0}
          <ul class="url-list">
            {#each client.LogoutURLs as url}
              <li><code>{url}</code></li>
            {/each}
          </ul>
        {:else}
          <p class="empty-text">No logout URLs configured</p>
        {/if}
      </section>

      <section class="detail-card full-width">
        <h2>Test Hosted UI</h2>
        <p class="help-text">Use this URL to test the hosted login UI:</p>
        <div class="url-box">
          <code>{getHostedUIUrl()}</code>
          <a href={getHostedUIUrl()} target="_blank" rel="noopener" class="btn btn-primary">
            Open Hosted UI
          </a>
        </div>
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

  .detail-card.full-width {
    grid-column: 1 / -1;
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
    width: 160px;
    flex-shrink: 0;
  }

  dd {
    margin: 0;
    color: #333;
    flex: 1;
  }

  dd code {
    background: #f5f5f5;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 13px;
    word-break: break-all;
  }

  .client-id-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .tags {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .tag {
    background: #e3f2fd;
    color: #1976d2;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
  }

  .url-list {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .url-list li {
    padding: 8px 0;
    border-bottom: 1px solid #eee;
  }

  .url-list li:last-child {
    border-bottom: none;
  }

  .url-list code {
    background: #f5f5f5;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 13px;
    word-break: break-all;
  }

  .empty-text {
    color: #999;
    font-size: 14px;
    margin: 0;
  }

  .help-text {
    color: #666;
    font-size: 14px;
    margin: 0 0 12px 0;
  }

  .url-box {
    background: #f5f5f5;
    padding: 16px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }

  .url-box code {
    flex: 1;
    min-width: 200px;
    word-break: break-all;
    font-size: 13px;
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
    text-decoration: none;
    display: inline-block;
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

  .btn-danger {
    background-color: #ffebee;
    color: #c62828;
  }

  .btn-danger:hover {
    background-color: #ffcdd2;
  }
</style>

<script lang="ts">
  import { onMount } from 'svelte'
  import type { AdminPage, UserPool, UserPoolClient } from '../lib/types'
  import { listUserPoolClients, createManagedLoginBranding, updateManagedLoginBranding } from '../lib/api'

  interface Props {
    userPool: UserPool
    navigate: (page: AdminPage, context?: { userPool?: UserPool }) => void
  }

  let { userPool, navigate }: Props = $props()

  let clients: UserPoolClient[] = $state([])
  let selectedClientId = $state('')
  let brandingId: string | null = $state(null)
  let loading = $state(true)
  let saving = $state(false)
  let error: string | null = $state(null)
  let success: string | null = $state(null)

  // Branding settings
  let pageTitle = $state('Sign In')
  let signInHeader = $state('Welcome')
  let signInSubheader = $state('Sign in to continue')
  let backgroundColor = $state('#f5f5f5')
  let primaryColor = $state('#007bff')
  let textColor = $state('#333333')
  let buttonColor = $state('#007bff')
  let buttonTextColor = $state('#ffffff')

  async function loadClients() {
    try {
      loading = true
      clients = await listUserPoolClients(userPool.Id)
      if (clients.length > 0) {
        selectedClientId = clients[0].ClientId
      }
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to load clients'
    } finally {
      loading = false
    }
  }

  async function handleSave() {
    if (!selectedClientId) {
      error = 'Please select a client'
      return
    }

    try {
      saving = true
      error = null

      const settings = {
        PageTitle: pageTitle,
        SignInHeader: signInHeader,
        SignInSubheader: signInSubheader,
        Colors: {
          BackgroundColor: backgroundColor,
          PrimaryColor: primaryColor,
          TextColor: textColor,
          ButtonColor: buttonColor,
          ButtonTextColor: buttonTextColor,
        },
      }

      if (brandingId) {
        await updateManagedLoginBranding(userPool.Id, brandingId, settings)
      } else {
        const branding = await createManagedLoginBranding(userPool.Id, selectedClientId, settings)
        brandingId = branding.ManagedLoginBrandingId
      }

      success = 'Branding saved successfully!'
      setTimeout(() => (success = null), 3000)
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to save branding'
    } finally {
      saving = false
    }
  }

  function getPreviewUrl(): string {
    if (!selectedClientId) return ''
    const client = clients.find(c => c.ClientId === selectedClientId)
    const callbackUrl = client?.CallbackURLs?.[0] || 'http://localhost:3000/callback'
    return `http://localhost:9229/ui/?response_type=code&client_id=${selectedClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
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
      <span>Branding</span>
    </div>
    <h1>Hosted UI Branding</h1>
    <p>Customize the appearance of your login page</p>
  </header>

  {#if error}
    <div class="error-banner">
      {error}
      <button class="btn-close" onclick={() => (error = null)}>Dismiss</button>
    </div>
  {/if}

  {#if success}
    <div class="success-banner">{success}</div>
  {/if}

  {#if loading}
    <div class="loading">Loading...</div>
  {:else if clients.length === 0}
    <div class="empty-state">
      <h2>No App Clients</h2>
      <p>Create an app client first to configure branding.</p>
      <button class="btn btn-primary" onclick={() => navigate('clients', { userPool })}>
        Create Client
      </button>
    </div>
  {:else}
    <div class="editor-layout">
      <div class="editor-form">
        <section class="form-section">
          <h2>App Client</h2>
          <div class="form-group">
            <label for="client">Select Client</label>
            <select id="client" bind:value={selectedClientId}>
              {#each clients as client}
                <option value={client.ClientId}>{client.ClientName}</option>
              {/each}
            </select>
          </div>
        </section>

        <section class="form-section">
          <h2>Text Content</h2>
          <div class="form-group">
            <label for="pageTitle">Page Title</label>
            <input type="text" id="pageTitle" bind:value={pageTitle} />
          </div>
          <div class="form-group">
            <label for="signInHeader">Sign In Header</label>
            <input type="text" id="signInHeader" bind:value={signInHeader} />
          </div>
          <div class="form-group">
            <label for="signInSubheader">Sign In Subheader</label>
            <input type="text" id="signInSubheader" bind:value={signInSubheader} />
          </div>
        </section>

        <section class="form-section">
          <h2>Colors</h2>
          <div class="color-grid">
            <div class="form-group">
              <label for="backgroundColor">Background</label>
              <div class="color-input">
                <input type="color" id="backgroundColor" bind:value={backgroundColor} />
                <input type="text" bind:value={backgroundColor} />
              </div>
            </div>
            <div class="form-group">
              <label for="primaryColor">Primary</label>
              <div class="color-input">
                <input type="color" id="primaryColor" bind:value={primaryColor} />
                <input type="text" bind:value={primaryColor} />
              </div>
            </div>
            <div class="form-group">
              <label for="textColor">Text</label>
              <div class="color-input">
                <input type="color" id="textColor" bind:value={textColor} />
                <input type="text" bind:value={textColor} />
              </div>
            </div>
            <div class="form-group">
              <label for="buttonColor">Button</label>
              <div class="color-input">
                <input type="color" id="buttonColor" bind:value={buttonColor} />
                <input type="text" bind:value={buttonColor} />
              </div>
            </div>
            <div class="form-group">
              <label for="buttonTextColor">Button Text</label>
              <div class="color-input">
                <input type="color" id="buttonTextColor" bind:value={buttonTextColor} />
                <input type="text" bind:value={buttonTextColor} />
              </div>
            </div>
          </div>
        </section>

        <div class="form-actions">
          <button class="btn btn-primary" onclick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save Branding'}
          </button>
          {#if selectedClientId}
            <a href={getPreviewUrl()} target="_blank" rel="noopener" class="btn btn-secondary">
              Preview
            </a>
          {/if}
        </div>
      </div>

      <div class="preview-panel">
        <h2>Preview</h2>
        <div class="preview-container" style="background-color: {backgroundColor}">
          <div class="preview-card">
            <h3 style="color: {textColor}">{signInHeader}</h3>
            <p style="color: {textColor}; opacity: 0.7">{signInSubheader}</p>
            <div class="preview-input">
              <span>Username</span>
            </div>
            <div class="preview-input">
              <span>Password</span>
            </div>
            <div
              class="preview-button"
              style="background-color: {buttonColor}; color: {buttonTextColor}"
            >
              Sign In
            </div>
            <div class="preview-link" style="color: {primaryColor}">
              Forgot password?
            </div>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .page {
    max-width: 1400px;
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

  .success-banner {
    background-color: #e8f5e9;
    border: 1px solid #c8e6c9;
    color: #2e7d32;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 24px;
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

  .editor-layout {
    display: grid;
    grid-template-columns: 1fr 400px;
    gap: 32px;
  }

  @media (max-width: 1024px) {
    .editor-layout {
      grid-template-columns: 1fr;
    }
  }

  .editor-form {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }

  .form-section {
    margin-bottom: 32px;
  }

  .form-section h2 {
    font-size: 16px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
    padding-bottom: 8px;
    border-bottom: 1px solid #eee;
  }

  .form-group {
    margin-bottom: 16px;
  }

  .form-group label {
    display: block;
    margin-bottom: 6px;
    font-size: 14px;
    font-weight: 500;
    color: #333;
  }

  .form-group input[type="text"],
  .form-group select {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
  }

  .form-group input:focus,
  .form-group select:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .color-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
  }

  .color-input {
    display: flex;
    gap: 8px;
  }

  .color-input input[type="color"] {
    width: 40px;
    height: 40px;
    padding: 0;
    border: 1px solid #ddd;
    border-radius: 6px;
    cursor: pointer;
  }

  .color-input input[type="text"] {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
    font-family: monospace;
  }

  .form-actions {
    display: flex;
    gap: 12px;
    padding-top: 16px;
    border-top: 1px solid #eee;
  }

  .preview-panel {
    background: white;
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
    position: sticky;
    top: 24px;
    height: fit-content;
  }

  .preview-panel h2 {
    font-size: 16px;
    font-weight: 600;
    margin: 0 0 16px 0;
    color: #1a1a2e;
  }

  .preview-container {
    padding: 32px 16px;
    border-radius: 8px;
    min-height: 400px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .preview-card {
    background: white;
    padding: 32px;
    border-radius: 8px;
    width: 100%;
    max-width: 300px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  }

  .preview-card h3 {
    font-size: 20px;
    font-weight: 600;
    margin: 0 0 8px 0;
    text-align: center;
  }

  .preview-card p {
    font-size: 13px;
    margin: 0 0 24px 0;
    text-align: center;
  }

  .preview-input {
    background: #f5f5f5;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 12px;
    font-size: 13px;
    color: #999;
  }

  .preview-button {
    padding: 12px;
    border-radius: 4px;
    text-align: center;
    font-weight: 500;
    font-size: 14px;
    margin-bottom: 16px;
  }

  .preview-link {
    text-align: center;
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
    padding: 12px 24px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    text-decoration: none;
    display: inline-block;
    text-align: center;
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

  .btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>

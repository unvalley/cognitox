<script lang="ts">
  import type { OAuthParams, Branding, Page } from '../lib/types'
  import { confirmSignup } from '../lib/api'
  import Card from '../lib/Card.svelte'

  interface Props {
    oauth: OAuthParams
    branding: Branding
    username: string
    error?: string
    success?: string
    navigate: (page: Page, params?: { username?: string }) => void
    setError: (msg: string) => void
    setSuccess: (msg: string) => void
  }

  let { oauth, branding, username, error, success, navigate, setError, setSuccess }: Props = $props()

  let code = $state('')
  let submitting = $state(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    submitting = true

    const result = await confirmSignup(username, code, oauth.client_id)

    if (result.success) {
      setSuccess('Account confirmed! You can now sign in.')
      setTimeout(() => {
        navigate('login')
      }, 1500)
    } else {
      setError(result.error || 'Confirmation failed')
      submitting = false
    }
  }
</script>

<Card {branding}>
  <h1>Confirm Your Account</h1>
  <p class="subheader">Enter the confirmation code sent to your email</p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if success}
    <div class="success">{success}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="form-group">
      <label for="code">Confirmation Code</label>
      <input
        type="text"
        id="code"
        bind:value={code}
        required
        disabled={submitting}
        placeholder="Enter 6-digit code"
        autocomplete="one-time-code"
      />
    </div>

    <button type="submit" class="btn btn-primary" disabled={submitting}>
      {submitting ? 'Confirming...' : 'Confirm'}
    </button>
  </form>

  <div class="links">
    <button type="button" class="link-btn" onclick={() => navigate('login')}>
      Back to Sign In
    </button>
  </div>
</Card>

<style>
  h1 {
    font-size: 24px;
    font-weight: 600;
    text-align: center;
    margin-bottom: 8px;
  }

  .subheader {
    text-align: center;
    color: #666;
    margin-bottom: 24px;
    font-size: 14px;
  }

  .error {
    background-color: #fee;
    border: 1px solid #fcc;
    color: #c00;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
    font-size: 14px;
  }

  .success {
    background-color: #efe;
    border: 1px solid #cfc;
    color: #060;
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 16px;
    font-size: 14px;
  }

  .form-group {
    margin-bottom: 16px;
  }

  label {
    display: block;
    margin-bottom: 6px;
    font-size: 14px;
    font-weight: 500;
  }

  input {
    width: 100%;
    padding: 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 16px;
    transition: border-color 0.2s;
  }

  input:focus {
    outline: none;
    border-color: var(--primary-color);
  }

  input:disabled {
    background-color: #f5f5f5;
    cursor: not-allowed;
  }

  .btn {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 4px;
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  .btn:hover:not(:disabled) {
    opacity: 0.9;
  }

  .btn:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-primary {
    background-color: var(--button-color, var(--primary-color));
    color: var(--button-text-color, white);
  }

  .links {
    margin-top: 24px;
    text-align: center;
  }

  .link-btn {
    background: none;
    border: none;
    color: var(--primary-color);
    cursor: pointer;
    font-size: 14px;
    text-decoration: underline;
  }

  .link-btn:hover {
    opacity: 0.8;
  }
</style>

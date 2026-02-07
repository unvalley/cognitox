<script lang="ts">
  import type { OAuthParams, Branding, Page } from '../lib/types'
  import { confirmForgotPassword } from '../lib/api'
  import Card from '../lib/Card.svelte'

  interface Props {
    oauth: OAuthParams
    branding: Branding
    username: string
    error?: string
    navigate: (page: Page, params?: { username?: string }) => void
    setError: (msg: string) => void
  }

  let { oauth, branding, username, error, navigate, setError }: Props = $props()

  let code = $state('')
  let newPassword = $state('')
  let newPasswordConfirm = $state('')
  let submitting = $state(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()

    if (newPassword !== newPasswordConfirm) {
      setError('Passwords do not match')
      return
    }

    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    submitting = true

    const result = await confirmForgotPassword(username, code, newPassword, oauth.client_id)

    if (result.success) {
      navigate('login')
    } else {
      setError(result.error || 'Reset failed')
      submitting = false
    }
  }
</script>

<Card {branding}>
  <h1>Set New Password</h1>
  <p class="subheader">Enter the code sent to your email and your new password</p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="form-group">
      <label for="code">Reset Code</label>
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

    <div class="form-group">
      <label for="newPassword">New Password</label>
      <input
        type="password"
        id="newPassword"
        bind:value={newPassword}
        required
        minlength="8"
        disabled={submitting}
        autocomplete="new-password"
      />
    </div>

    <div class="form-group">
      <label for="newPasswordConfirm">Confirm New Password</label>
      <input
        type="password"
        id="newPasswordConfirm"
        bind:value={newPasswordConfirm}
        required
        minlength="8"
        disabled={submitting}
        autocomplete="new-password"
      />
    </div>

    <button type="submit" class="btn btn-primary" disabled={submitting}>
      {submitting ? 'Resetting...' : 'Reset Password'}
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

<script lang="ts">
  import type { OAuthParams, Branding, Page } from '../lib/types'
  import { signup } from '../lib/api'
  import Card from '../lib/Card.svelte'

  interface Props {
    oauth: OAuthParams
    branding: Branding
    error?: string
    navigate: (page: Page, params?: { username?: string }) => void
    setError: (msg: string) => void
  }

  let { oauth, branding, error, navigate, setError }: Props = $props()

  let username = $state('')
  let email = $state('')
  let password = $state('')
  let passwordConfirm = $state('')
  let submitting = $state(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()

    if (password !== passwordConfirm) {
      setError('Passwords do not match')
      return
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    submitting = true

    const result = await signup(username, email, password, oauth.client_id)

    if (result.success) {
      navigate('confirm', { username })
    } else {
      setError(result.error || 'Signup failed')
      submitting = false
    }
  }
</script>

<Card {branding}>
  <h1>Create Account</h1>
  <p class="subheader">Sign up for a new account</p>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <form onsubmit={handleSubmit}>
    <div class="form-group">
      <label for="username">Username</label>
      <input
        type="text"
        id="username"
        bind:value={username}
        required
        disabled={submitting}
        autocomplete="username"
      />
    </div>

    <div class="form-group">
      <label for="email">Email</label>
      <input
        type="email"
        id="email"
        bind:value={email}
        required
        disabled={submitting}
        autocomplete="email"
      />
    </div>

    <div class="form-group">
      <label for="password">Password</label>
      <input
        type="password"
        id="password"
        bind:value={password}
        required
        minlength="8"
        disabled={submitting}
        autocomplete="new-password"
      />
    </div>

    <div class="form-group">
      <label for="passwordConfirm">Confirm Password</label>
      <input
        type="password"
        id="passwordConfirm"
        bind:value={passwordConfirm}
        required
        minlength="8"
        disabled={submitting}
        autocomplete="new-password"
      />
    </div>

    <button type="submit" class="btn btn-primary" disabled={submitting}>
      {submitting ? 'Creating account...' : 'Sign Up'}
    </button>
  </form>

  <div class="links">
    <button type="button" class="link-btn" onclick={() => navigate('login')}>
      Already have an account? Sign in
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

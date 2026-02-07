<script lang="ts">
  import { onMount } from 'svelte'
  import type { Page, OAuthParams, Branding } from './lib/types'
  import { getBranding } from './lib/api'
  import Login from './routes/Login.svelte'
  import Signup from './routes/Signup.svelte'
  import Confirm from './routes/Confirm.svelte'
  import ForgotPassword from './routes/ForgotPassword.svelte'
  import ResetPassword from './routes/ResetPassword.svelte'

  let page: Page = $state('login')
  let oauth: OAuthParams = $state({
    response_type: 'code',
    client_id: '',
    redirect_uri: '',
    scope: 'openid',
  })
  let branding: Branding = $state({
    pageTitle: 'Sign In',
    signInHeader: 'Welcome',
    signInSubheader: 'Sign in to continue',
    backgroundColor: '#f5f5f5',
    primaryColor: '#007bff',
    textColor: '#333333',
    buttonColor: '#007bff',
    buttonTextColor: '#ffffff',
  })
  let username: string = $state('')
  let error: string | undefined = $state(undefined)
  let success: string | undefined = $state(undefined)
  let loading: boolean = $state(true)

  function parseQueryParams(): void {
    const params = new URLSearchParams(window.location.search)

    oauth = {
      response_type: params.get('response_type') || 'code',
      client_id: params.get('client_id') || '',
      redirect_uri: params.get('redirect_uri') || '',
      scope: params.get('scope') || 'openid',
      state: params.get('state') || undefined,
      nonce: params.get('nonce') || undefined,
      code_challenge: params.get('code_challenge') || undefined,
      code_challenge_method: params.get('code_challenge_method') || undefined,
    }

    username = params.get('username') || ''

    // Determine page from path
    const path = window.location.pathname
    if (path.includes('signup')) {
      page = 'signup'
    } else if (path.includes('confirm')) {
      page = 'confirm'
    } else if (path.includes('forgot-password')) {
      page = 'forgot-password'
    } else if (path.includes('reset-password')) {
      page = 'reset-password'
    } else {
      page = 'login'
    }
  }

  function navigate(newPage: Page, params?: { username?: string }) {
    page = newPage
    if (params?.username) {
      username = params.username
    }
    error = undefined
    success = undefined

    // Update URL
    const searchParams = new URLSearchParams()
    searchParams.set('response_type', oauth.response_type)
    searchParams.set('client_id', oauth.client_id)
    searchParams.set('redirect_uri', oauth.redirect_uri)
    searchParams.set('scope', oauth.scope || 'openid')
    if (oauth.state) searchParams.set('state', oauth.state)
    if (oauth.nonce) searchParams.set('nonce', oauth.nonce)
    if (oauth.code_challenge) searchParams.set('code_challenge', oauth.code_challenge)
    if (oauth.code_challenge_method) searchParams.set('code_challenge_method', oauth.code_challenge_method)
    if (params?.username) searchParams.set('username', params.username)

    const newPath = `/${newPage === 'login' ? '' : newPage}`
    window.history.pushState({}, '', `${newPath}?${searchParams}`)
  }

  onMount(async () => {
    parseQueryParams()

    if (oauth.client_id) {
      branding = await getBranding(oauth.client_id)
    }

    // Apply branding as CSS variables
    document.documentElement.style.setProperty('--primary-color', branding.primaryColor)
    document.documentElement.style.setProperty('--background-color', branding.backgroundColor)
    document.documentElement.style.setProperty('--text-color', branding.textColor)
    document.documentElement.style.setProperty('--button-color', branding.buttonColor)
    document.documentElement.style.setProperty('--button-text-color', branding.buttonTextColor)
    document.title = branding.pageTitle

    loading = false
  })

  function setError(msg: string) {
    error = msg
    success = undefined
  }

  function setSuccess(msg: string) {
    success = msg
    error = undefined
  }
</script>

{#if loading}
  <div class="loading">Loading...</div>
{:else if !oauth.client_id}
  <div class="error-container">
    <h1>Missing Parameters</h1>
    <p>client_id and redirect_uri are required.</p>
  </div>
{:else}
  {#if page === 'login'}
    <Login {oauth} {branding} {error} {navigate} {setError} />
  {:else if page === 'signup'}
    <Signup {oauth} {branding} {error} {navigate} {setError} />
  {:else if page === 'confirm'}
    <Confirm {oauth} {branding} {username} {error} {success} {navigate} {setError} {setSuccess} />
  {:else if page === 'forgot-password'}
    <ForgotPassword {oauth} {branding} {error} {navigate} />
  {:else if page === 'reset-password'}
    <ResetPassword {oauth} {branding} {username} {error} {navigate} {setError} />
  {/if}
{/if}

<style>
  .loading {
    text-align: center;
    padding: 40px;
    font-size: 18px;
    color: #666;
  }

  .error-container {
    background: white;
    padding: 40px;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }

  .error-container h1 {
    color: var(--error-color);
    margin-bottom: 16px;
  }
</style>

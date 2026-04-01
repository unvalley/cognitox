import { useState } from 'preact/hooks'
import type { OAuthParams, Branding, Page } from '../lib/types'
import { login, standaloneLogin } from '../lib/api'
import { Card } from '../lib/Card'

interface Props {
  oauth: OAuthParams
  branding: Branding
  error?: string
  navigate: (page: Page, params?: { username?: string }) => void
  setError: (msg: string) => void
  standalone?: boolean
}

export function Login({ oauth, branding, error, navigate, setError, standalone }: Props) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    setSubmitting(true)

    if (standalone) {
      const result = await standaloneLogin(username, password, oauth.client_id)
      if (result.success) {
        window.location.href = '/admin/'
        return
      } else {
        setError(result.error || 'Login failed')
      }
      setSubmitting(false)
    } else {
      const result = await login(username, password, oauth)
      if (result.success && result.redirectUrl) {
        window.location.href = result.redirectUrl
      } else {
        setError(result.error || 'Login failed')
        setSubmitting(false)
      }
    }
  }

  return (
    <Card branding={branding}>
      <h1 class="text-2xl font-semibold text-center mb-2">{branding.signInHeader}</h1>
      <p class="text-center text-sm text-base-content/60 mb-6">{branding.signInSubheader}</p>

      {error && <div class="alert alert-error text-sm mb-4">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Username</span></label>
          <input type="text" class="input input-bordered w-full" value={username} onInput={e => setUsername((e.target as HTMLInputElement).value)} required disabled={submitting} autoComplete="username" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Password</span></label>
          <input type="password" class="input input-bordered w-full" value={password} onInput={e => setPassword((e.target as HTMLInputElement).value)} required disabled={submitting} autoComplete="current-password" />
        </div>
        <button type="submit" class="btn btn-primary w-full" disabled={submitting} style={{ backgroundColor: 'var(--button-color)', color: 'var(--button-text-color)' }}>
          {submitting ? <><span class="loading loading-spinner loading-sm"></span> Signing in...</> : 'Sign In'}
        </button>
      </form>

      <div class="text-center mt-6 space-y-3">
        <button class="link link-primary text-sm" onClick={() => navigate('forgot-password')}>Forgot password?</button>
        <div class="text-xs text-base-content/40">or</div>
        <button class="link link-primary text-sm" onClick={() => navigate('signup')}>Create an account</button>
      </div>
    </Card>
  )
}

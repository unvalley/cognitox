import { useState } from 'preact/hooks'
import type { OAuthParams, Branding, Page } from '../lib/types'
import { forgotPassword } from '../lib/api'
import { Card } from '../lib/Card'

interface Props {
  oauth: OAuthParams
  branding: Branding
  error?: string
  navigate: (page: Page, params?: { username?: string }) => void
}

export function ForgotPassword({ oauth, branding, error, navigate }: Props) {
  const [username, setUsername] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    setSubmitting(true)
    await forgotPassword(username, oauth.client_id)
    navigate('reset-password', { username })
  }

  return (
    <Card branding={branding}>
      <h1 class="text-2xl font-semibold text-center mb-2">Reset Password</h1>
      <p class="text-center text-sm text-base-content/60 mb-6">Enter your username to receive a reset code</p>

      {error && <div class="alert alert-error text-sm mb-4">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Username</span></label>
          <input type="text" class="input input-bordered" value={username} onInput={e => setUsername((e.target as HTMLInputElement).value)} required disabled={submitting} autoComplete="username" />
        </div>
        <button type="submit" class="btn btn-primary w-full" disabled={submitting} style={{ backgroundColor: 'var(--button-color)', color: 'var(--button-text-color)' }}>
          {submitting ? <><span class="loading loading-spinner loading-sm"></span> Sending...</> : 'Send Reset Code'}
        </button>
      </form>

      <div class="text-center mt-6">
        <button class="link link-primary text-sm" onClick={() => navigate('login')}>Back to Sign In</button>
      </div>
    </Card>
  )
}

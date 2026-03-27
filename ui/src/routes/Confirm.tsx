import { useState } from 'preact/hooks'
import type { OAuthParams, Branding, Page } from '../lib/types'
import { confirmSignup } from '../lib/api'
import { Card } from '../lib/Card'

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

export function Confirm({ oauth, branding, username, error, success, navigate, setError, setSuccess }: Props) {
  const [code, setCode] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    setSubmitting(true)
    const result = await confirmSignup(username, code, oauth.client_id)
    if (result.success) {
      setSuccess('Account confirmed! You can now sign in.')
      setTimeout(() => navigate('login'), 1500)
    } else {
      setError(result.error || 'Confirmation failed')
      setSubmitting(false)
    }
  }

  return (
    <Card branding={branding}>
      <h1 class="text-2xl font-semibold text-center mb-2">Confirm Your Account</h1>
      <p class="text-center text-sm text-base-content/60 mb-6">Enter the confirmation code sent to your email</p>

      {error && <div class="alert alert-error text-sm mb-4">{error}</div>}
      {success && <div class="alert alert-success text-sm mb-4">{success}</div>}

      <form onSubmit={handleSubmit}>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Confirmation Code</span></label>
          <input type="text" class="input input-bordered" value={code} onInput={e => setCode((e.target as HTMLInputElement).value)} required disabled={submitting} placeholder="Enter 6-digit code" autoComplete="one-time-code" />
        </div>
        <button type="submit" class="btn btn-primary w-full" disabled={submitting} style={{ backgroundColor: 'var(--button-color)', color: 'var(--button-text-color)' }}>
          {submitting ? <><span class="loading loading-spinner loading-sm"></span> Confirming...</> : 'Confirm'}
        </button>
      </form>

      <div class="text-center mt-6">
        <button class="link link-primary text-sm" onClick={() => navigate('login')}>Back to Sign In</button>
      </div>
    </Card>
  )
}

import { useState } from 'preact/hooks'
import type { OAuthParams, Branding, Page } from '../lib/types'
import { confirmForgotPassword } from '../lib/api'
import { Card } from '../lib/Card'

interface Props {
  oauth: OAuthParams
  branding: Branding
  username: string
  error?: string
  navigate: (page: Page, params?: { username?: string }) => void
  setError: (msg: string) => void
}

export function ResetPassword({ oauth, branding, username, error, navigate, setError }: Props) {
  const [code, setCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (newPassword !== newPasswordConfirm) { setError('Passwords do not match'); return }
    if (newPassword.length < 8) { setError('Password must be at least 8 characters'); return }

    setSubmitting(true)
    const result = await confirmForgotPassword(username, code, newPassword, oauth.client_id)
    if (result.success) {
      navigate('login')
    } else {
      setError(result.error || 'Reset failed')
      setSubmitting(false)
    }
  }

  return (
    <Card branding={branding}>
      <h1 class="text-2xl font-semibold text-center mb-2">Set New Password</h1>
      <p class="text-center text-sm text-base-content/60 mb-6">Enter the code sent to your email and your new password</p>

      {error && <div class="alert alert-error text-sm mb-4">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Reset Code</span></label>
          <input type="text" class="input input-bordered w-full" value={code} onInput={e => setCode((e.target as HTMLInputElement).value)} required disabled={submitting} placeholder="Enter 6-digit code" autoComplete="one-time-code" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">New Password</span></label>
          <input type="password" class="input input-bordered w-full" value={newPassword} onInput={e => setNewPassword((e.target as HTMLInputElement).value)} required minLength={8} disabled={submitting} autoComplete="new-password" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Confirm New Password</span></label>
          <input type="password" class="input input-bordered w-full" value={newPasswordConfirm} onInput={e => setNewPasswordConfirm((e.target as HTMLInputElement).value)} required minLength={8} disabled={submitting} autoComplete="new-password" />
        </div>
        <button type="submit" class="btn btn-primary w-full" disabled={submitting} style={{ backgroundColor: 'var(--button-color)', color: 'var(--button-text-color)' }}>
          {submitting ? <><span class="loading loading-spinner loading-sm"></span> Resetting...</> : 'Reset Password'}
        </button>
      </form>

      <div class="text-center mt-6">
        <button class="link link-primary text-sm" onClick={() => navigate('login')}>Back to Sign In</button>
      </div>
    </Card>
  )
}

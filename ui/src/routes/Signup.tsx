import { useState } from 'preact/hooks'
import type { OAuthParams, Branding, Page } from '../lib/types'
import { signup } from '../lib/api'
import { Card } from '../lib/Card'

interface Props {
  oauth: OAuthParams
  branding: Branding
  error?: string
  navigate: (page: Page, params?: { username?: string }) => void
  setError: (msg: string) => void
}

export function Signup({ oauth, branding, error, navigate, setError }: Props) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [passwordConfirm, setPasswordConfirm] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (password !== passwordConfirm) { setError('Passwords do not match'); return }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return }

    setSubmitting(true)
    const result = await signup(username, email, password, oauth.client_id)
    if (result.success) {
      navigate('confirm', { username })
    } else {
      setError(result.error || 'Signup failed')
      setSubmitting(false)
    }
  }

  return (
    <Card branding={branding}>
      <h1 class="text-2xl font-semibold text-center mb-2">Create Account</h1>
      <p class="text-center text-sm text-base-content/60 mb-6">Sign up for a new account</p>

      {error && <div class="alert alert-error text-sm mb-4">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Username</span></label>
          <input type="text" class="input input-bordered w-full" value={username} onInput={e => setUsername((e.target as HTMLInputElement).value)} required disabled={submitting} autoComplete="username" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Email</span></label>
          <input type="email" class="input input-bordered w-full" value={email} onInput={e => setEmail((e.target as HTMLInputElement).value)} required disabled={submitting} autoComplete="email" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Password</span></label>
          <input type="password" class="input input-bordered w-full" value={password} onInput={e => setPassword((e.target as HTMLInputElement).value)} required minLength={8} disabled={submitting} autoComplete="new-password" />
        </div>
        <div class="form-control mb-4">
          <label class="label"><span class="label-text">Confirm Password</span></label>
          <input type="password" class="input input-bordered w-full" value={passwordConfirm} onInput={e => setPasswordConfirm((e.target as HTMLInputElement).value)} required minLength={8} disabled={submitting} autoComplete="new-password" />
        </div>
        <button type="submit" class="btn btn-primary w-full" disabled={submitting} style={{ backgroundColor: 'var(--button-color)', color: 'var(--button-text-color)' }}>
          {submitting ? <><span class="loading loading-spinner loading-sm"></span> Creating account...</> : 'Sign Up'}
        </button>
      </form>

      <div class="text-center mt-6">
        <button class="link link-primary text-sm" onClick={() => navigate('login')}>Already have an account? Sign in</button>
      </div>
    </Card>
  )
}

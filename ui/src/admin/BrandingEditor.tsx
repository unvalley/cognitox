import { useState, useEffect } from 'preact/hooks'
import type { UserPool, User, UserPoolClient } from '../lib/types'
import { listUserPoolClients, createManagedLoginBranding, updateManagedLoginBranding } from '../lib/api'

interface Props {
  userPool: UserPool
  navigate: (path: string, context?: { userPool?: UserPool; user?: User; client?: UserPoolClient }) => void
}

export function BrandingEditor({ userPool, navigate }: Props) {
  const [clients, setClients] = useState<UserPoolClient[]>([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const [brandingId, setBrandingId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [pageTitle, setPageTitle] = useState('Sign In')
  const [signInHeader, setSignInHeader] = useState('Welcome')
  const [signInSubheader, setSignInSubheader] = useState('Sign in to continue')
  const [backgroundColor, setBackgroundColor] = useState('#f5f5f5')
  const [primaryColor, setPrimaryColor] = useState('#007bff')
  const [textColor, setTextColor] = useState('#333333')
  const [buttonColor, setButtonColor] = useState('#007bff')
  const [buttonTextColor, setButtonTextColor] = useState('#ffffff')

  useEffect(() => {
    listUserPoolClients(userPool.Id)
      .then(c => {
        setClients(c)
        if (c.length > 0) setSelectedClientId(c[0].ClientId)
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Failed to load clients'))
      .finally(() => setLoading(false))
  }, [userPool.Id])

  async function handleSave() {
    if (!selectedClientId) { setError('Please select a client'); return }
    try {
      setSaving(true)
      setError(null)
      const settings = {
        PageTitle: pageTitle,
        SignInHeader: signInHeader,
        SignInSubheader: signInSubheader,
        Colors: { BackgroundColor: backgroundColor, PrimaryColor: primaryColor, TextColor: textColor, ButtonColor: buttonColor, ButtonTextColor: buttonTextColor },
      }
      if (brandingId) {
        await updateManagedLoginBranding(userPool.Id, brandingId, settings)
      } else {
        const branding = await createManagedLoginBranding(userPool.Id, selectedClientId, settings)
        setBrandingId(branding.ManagedLoginBrandingId)
      }
      setSuccess('Branding saved successfully!')
      setTimeout(() => setSuccess(null), 3000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save branding')
    } finally {
      setSaving(false)
    }
  }

  function getPreviewUrl(): string {
    if (!selectedClientId) return ''
    const client = clients.find(c => c.ClientId === selectedClientId)
    const callbackUrl = client?.CallbackURLs?.[0] || 'http://localhost:3000/callback'
    return `http://localhost:9229/ui/?response_type=code&client_id=${selectedClientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&scope=openid`
  }

  const colorFields = [
    { label: 'Background', value: backgroundColor, setter: setBackgroundColor },
    { label: 'Primary', value: primaryColor, setter: setPrimaryColor },
    { label: 'Text', value: textColor, setter: setTextColor },
    { label: 'Button', value: buttonColor, setter: setButtonColor },
    { label: 'Button Text', value: buttonTextColor, setter: setButtonTextColor },
  ]

  return (
    <div class="max-w-7xl">
      <div class="mb-8">
        <div class="breadcrumbs text-sm mb-2">
          <ul>
            <li><button class="link link-primary" onClick={() => navigate('/admin/pools')}>User Pools</button></li>
            <li><button class="link link-primary" onClick={() => navigate(`/admin/pools/${userPool.Id}`)}>{userPool.Name}</button></li>
            <li>Branding</li>
          </ul>
        </div>
        <h1 class="text-3xl font-bold">Hosted UI Branding</h1>
        <p class="text-base-content/60">Customize the appearance of your login page</p>
      </div>

      {error && (
        <div class="alert alert-error mb-6">
          <span>{error}</span>
          <button class="btn btn-ghost btn-sm" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}
      {success && <div class="alert alert-success mb-6">{success}</div>}

      {loading ? (
        <div class="flex justify-center p-10"><span class="loading loading-spinner loading-lg"></span></div>
      ) : clients.length === 0 ? (
        <div class="card bg-base-100 shadow">
          <div class="card-body items-center text-center py-16">
            <h2 class="card-title">No App Clients</h2>
            <p class="text-base-content/60">Create an app client first to configure branding.</p>
            <button class="btn btn-primary mt-4" onClick={() => navigate(`/admin/pools/${userPool.Id}/clients`)}>Create Client</button>
          </div>
        </div>
      ) : (
        <div class="grid grid-cols-1 xl:grid-cols-[1fr_400px] gap-8">
          <div class="card bg-base-100 shadow">
            <div class="card-body">
              <h2 class="text-lg font-semibold border-b border-base-200 pb-2 mb-5">App Client</h2>
              <div class="form-control mb-8">
                <label class="label pb-1.5"><span class="label-text">Select Client</span></label>
                <select class="select select-bordered" value={selectedClientId} onChange={e => setSelectedClientId((e.target as HTMLSelectElement).value)}>
                  {clients.map(c => <option key={c.ClientId} value={c.ClientId}>{c.ClientName}</option>)}
                </select>
              </div>

              <h2 class="text-lg font-semibold border-b border-base-200 pb-2 mb-5">Text Content</h2>
              <div class="form-control mb-5">
                <label class="label pb-1.5"><span class="label-text">Page Title</span></label>
                <input type="text" class="input input-bordered" value={pageTitle} onInput={e => setPageTitle((e.target as HTMLInputElement).value)} />
              </div>
              <div class="form-control mb-5">
                <label class="label pb-1.5"><span class="label-text">Sign In Header</span></label>
                <input type="text" class="input input-bordered" value={signInHeader} onInput={e => setSignInHeader((e.target as HTMLInputElement).value)} />
              </div>
              <div class="form-control mb-8">
                <label class="label pb-1.5"><span class="label-text">Sign In Subheader</span></label>
                <input type="text" class="input input-bordered" value={signInSubheader} onInput={e => setSignInSubheader((e.target as HTMLInputElement).value)} />
              </div>

              <h2 class="text-lg font-semibold border-b border-base-200 pb-2 mb-5">Colors</h2>
              <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 mb-8">
                {colorFields.map(({ label, value, setter }) => (
                  <div key={label} class="form-control">
                    <label class="label"><span class="label-text">{label}</span></label>
                    <div class="flex gap-2">
                      <input type="color" class="w-10 h-10 rounded cursor-pointer border border-base-300" value={value} onInput={e => setter((e.target as HTMLInputElement).value)} />
                      <input type="text" class="input input-bordered input-sm flex-1 font-mono" value={value} onInput={e => setter((e.target as HTMLInputElement).value)} />
                    </div>
                  </div>
                ))}
              </div>

              <div class="flex gap-3 pt-4 border-t border-base-200">
                <button class="btn btn-primary" onClick={handleSave} disabled={saving}>
                  {saving ? <><span class="loading loading-spinner loading-sm"></span> Saving...</> : 'Save Branding'}
                </button>
                {selectedClientId && (
                  <a href={getPreviewUrl()} target="_blank" rel="noopener" class="btn btn-outline">Preview</a>
                )}
              </div>
            </div>
          </div>

          <div class="card bg-base-100 shadow sticky top-6 h-fit">
            <div class="card-body">
              <h2 class="text-lg font-semibold mb-4">Preview</h2>
              <div class="rounded-lg p-8 min-h-96 flex items-center justify-center" style={{ backgroundColor }}>
                <div class="bg-white rounded-lg p-8 w-full max-w-xs shadow-lg">
                  <h3 class="text-xl font-semibold text-center mb-2" style={{ color: textColor }}>{signInHeader}</h3>
                  <p class="text-center text-sm mb-6" style={{ color: textColor, opacity: 0.7 }}>{signInSubheader}</p>
                  <div class="bg-gray-100 rounded p-3 mb-3 text-sm text-gray-400">Username</div>
                  <div class="bg-gray-100 rounded p-3 mb-3 text-sm text-gray-400">Password</div>
                  <div class="rounded p-3 text-center font-medium text-sm mb-4" style={{ backgroundColor: buttonColor, color: buttonTextColor }}>Sign In</div>
                  <div class="text-center text-sm" style={{ color: primaryColor }}>Forgot password?</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

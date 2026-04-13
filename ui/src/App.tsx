import { useState, useEffect } from 'preact/hooks'
import type { Page, OAuthParams, Branding } from './lib/types'
import { getBranding, listUserPools, listUserPoolClients } from './lib/api'
import { Login } from './routes/Login'
import { Signup } from './routes/Signup'
import { Confirm } from './routes/Confirm'
import { ForgotPassword } from './routes/ForgotPassword'
import { ResetPassword } from './routes/ResetPassword'

export function HostedUiApp() {
  const [page, setPage] = useState<Page>('login')
  const [oauth, setOauth] = useState<OAuthParams>({
    response_type: 'code',
    client_id: '',
    redirect_uri: '',
    scope: 'openid',
  })
  const [branding, setBranding] = useState<Branding>({
    pageTitle: 'Sign In',
    signInHeader: 'Welcome',
    signInSubheader: 'Sign in to continue',
    backgroundColor: '#f5f5f5',
    primaryColor: '#007bff',
    textColor: '#333333',
    buttonColor: '#007bff',
    buttonTextColor: '#ffffff',
  })
  const [username, setUsername] = useState('')
  const [error, setErrorState] = useState<string | undefined>(undefined)
  const [success, setSuccessState] = useState<string | undefined>(undefined)
  const [loading, setLoading] = useState(true)

  function setError(msg: string) {
    setErrorState(msg)
    setSuccessState(undefined)
  }

  function setSuccess(msg: string) {
    setSuccessState(msg)
    setErrorState(undefined)
  }

  function getBasePath(pathname: string): string {
    if (pathname === '/ui' || pathname.startsWith('/ui/')) {
      return '/ui'
    }

    return ''
  }

  function getPageFromPath(pathname: string): Page {
    if (pathname.endsWith('/signup')) return 'signup'
    if (pathname.endsWith('/confirm')) return 'confirm'
    if (pathname.endsWith('/forgot-password')) return 'forgot-password'
    if (pathname.endsWith('/reset-password')) return 'reset-password'
    return 'login'
  }

  function buildSearchParams(params?: { username?: string }): URLSearchParams {
    const searchParams = new URLSearchParams()
    searchParams.set('response_type', oauth.response_type)
    searchParams.set('client_id', oauth.client_id)
    searchParams.set('redirect_uri', oauth.redirect_uri)
    searchParams.set('scope', oauth.scope || 'openid')
    if (oauth.state) searchParams.set('state', oauth.state)
    if (oauth.nonce) searchParams.set('nonce', oauth.nonce)
    if (oauth.code_challenge) searchParams.set('code_challenge', oauth.code_challenge)
    if (oauth.code_challenge_method) searchParams.set('code_challenge_method', oauth.code_challenge_method)
    if (params?.username) {
      searchParams.set('username', params.username)
    } else if (username) {
      searchParams.set('username', username)
    }

    return searchParams
  }

  function getPagePath(pageName: Page): string {
    const suffix = pageName === 'login' ? '' : `/${pageName}`
    const basePath = getBasePath(window.location.pathname)
    return `${basePath}${suffix || '/'}`
  }

  function syncFromLocation(): OAuthParams {
    const params = new URLSearchParams(window.location.search)
    const oauthParams: OAuthParams = {
      response_type: params.get('response_type') || 'code',
      client_id: params.get('client_id') || '',
      redirect_uri: params.get('redirect_uri') || '',
      scope: params.get('scope') || 'openid',
      state: params.get('state') || undefined,
      nonce: params.get('nonce') || undefined,
      code_challenge: params.get('code_challenge') || undefined,
      code_challenge_method: params.get('code_challenge_method') || undefined,
    }

    setOauth(oauthParams)
    setUsername(params.get('username') || '')
    setPage(getPageFromPath(window.location.pathname))

    return oauthParams
  }

  function navigate(newPage: Page, params?: { username?: string }) {
    setPage(newPage)
    if (params?.username) setUsername(params.username)
    setErrorState(undefined)
    setSuccessState(undefined)

    const searchParams = buildSearchParams(params)
    const nextUrl = `${getPagePath(newPage)}?${searchParams.toString()}`
    window.history.pushState({ page: newPage }, '', nextUrl)
  }

  useEffect(() => {
    const oauthParams = syncFromLocation()

    ;(async () => {
      let clientId = oauthParams.client_id

      // Auto-detect a client_id if not provided
      if (!clientId) {
        try {
          const pools = await listUserPools()
          if (pools.length > 0) {
            const clients = await listUserPoolClients(pools[0].Id)
            if (clients.length > 0) {
              clientId = clients[0].ClientId
              setOauth(prev => ({ ...prev, client_id: clientId }))
            }
          }
        } catch {
          // Ignore - will show login without OAuth
        }
      }

      if (clientId) {
        const b = await getBranding(clientId)
        setBranding(b)
        document.documentElement.style.setProperty('--primary-color', b.primaryColor)
        document.documentElement.style.setProperty('--background-color', b.backgroundColor)
        document.documentElement.style.setProperty('--text-color', b.textColor)
        document.documentElement.style.setProperty('--button-color', b.buttonColor)
        document.documentElement.style.setProperty('--button-text-color', b.buttonTextColor)
        document.title = b.pageTitle
      }
      setLoading(false)
    })()

    const handlePopState = () => {
      setErrorState(undefined)
      setSuccessState(undefined)
      syncFromLocation()
    }

    window.addEventListener('popstate', handlePopState)

    return () => {
      window.removeEventListener('popstate', handlePopState)
    }
  }, [])

  if (loading) {
    return <div class="flex items-center justify-center min-h-screen"><span class="loading loading-spinner loading-lg"></span></div>
  }

  const isStandalone = !oauth.redirect_uri

  return (
    <div class="flex items-center justify-center min-h-screen p-5" style={{ backgroundColor: 'var(--background-color)' }}>
      {page === 'login' && <Login oauth={oauth} branding={branding} error={error} navigate={navigate} setError={setError} standalone={isStandalone} />}
      {page === 'signup' && <Signup oauth={oauth} branding={branding} error={error} navigate={navigate} setError={setError} />}
      {page === 'confirm' && <Confirm oauth={oauth} branding={branding} username={username} error={error} success={success} navigate={navigate} setError={setError} setSuccess={setSuccess} />}
      {page === 'forgot-password' && <ForgotPassword oauth={oauth} branding={branding} error={error} navigate={navigate} />}
      {page === 'reset-password' && <ResetPassword oauth={oauth} branding={branding} username={username} error={error} navigate={navigate} setError={setError} />}
    </div>
  )
}

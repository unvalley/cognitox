import type { OAuthParams, Branding } from './types'

const API_BASE = 'http://localhost:9229'

export async function login(
  username: string,
  password: string,
  oauth: OAuthParams
): Promise<{ success: boolean; redirectUrl?: string; error?: string }> {
  const params = new URLSearchParams({
    response_type: oauth.response_type,
    client_id: oauth.client_id,
    redirect_uri: oauth.redirect_uri,
    scope: oauth.scope || 'openid',
    username,
    password,
  })

  if (oauth.state) params.set('state', oauth.state)
  if (oauth.nonce) params.set('nonce', oauth.nonce)
  if (oauth.code_challenge) params.set('code_challenge', oauth.code_challenge)
  if (oauth.code_challenge_method) params.set('code_challenge_method', oauth.code_challenge_method)

  try {
    const response = await fetch(`${API_BASE}/oauth2/authorize?${params}`, {
      method: 'GET',
      redirect: 'manual',
    })

    if (response.type === 'opaqueredirect' || response.status === 302 || response.status === 307) {
      const location = response.headers.get('Location')
      if (location) {
        return { success: true, redirectUrl: location }
      }
    }

    // If we get a redirect URL in the response
    if (response.redirected) {
      return { success: true, redirectUrl: response.url }
    }

    const data = await response.json()
    return { success: false, error: data.error_description || data.error || 'Login failed' }
  } catch (e) {
    return { success: false, error: 'Network error' }
  }
}

export async function signup(
  username: string,
  email: string,
  password: string,
  clientId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.SignUp',
      },
      body: JSON.stringify({
        ClientId: clientId,
        Username: username,
        Password: password,
        UserAttributes: [{ Name: 'email', Value: email }],
      }),
    })

    const data = await response.json()

    if (response.ok) {
      return { success: true }
    }

    return { success: false, error: data.message || data.__type || 'Signup failed' }
  } catch (e) {
    return { success: false, error: 'Network error' }
  }
}

export async function confirmSignup(
  username: string,
  code: string,
  clientId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmSignUp',
      },
      body: JSON.stringify({
        ClientId: clientId,
        Username: username,
        ConfirmationCode: code,
      }),
    })

    const data = await response.json()

    if (response.ok) {
      return { success: true }
    }

    return { success: false, error: data.message || data.__type || 'Confirmation failed' }
  } catch (e) {
    return { success: false, error: 'Network error' }
  }
}

export async function forgotPassword(
  username: string,
  clientId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ForgotPassword',
      },
      body: JSON.stringify({
        ClientId: clientId,
        Username: username,
      }),
    })

    const data = await response.json()

    if (response.ok) {
      return { success: true }
    }

    return { success: false, error: data.message || data.__type || 'Request failed' }
  } catch (e) {
    return { success: false, error: 'Network error' }
  }
}

export async function confirmForgotPassword(
  username: string,
  code: string,
  newPassword: string,
  clientId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.ConfirmForgotPassword',
      },
      body: JSON.stringify({
        ClientId: clientId,
        Username: username,
        ConfirmationCode: code,
        Password: newPassword,
      }),
    })

    const data = await response.json()

    if (response.ok) {
      return { success: true }
    }

    return { success: false, error: data.message || data.__type || 'Reset failed' }
  } catch (e) {
    return { success: false, error: 'Network error' }
  }
}

export async function getBranding(clientId: string): Promise<Branding> {
  // Default branding
  const defaultBranding: Branding = {
    pageTitle: 'Sign In',
    signInHeader: 'Welcome',
    signInSubheader: 'Sign in to continue',
    backgroundColor: '#f5f5f5',
    primaryColor: '#007bff',
    textColor: '#333333',
    buttonColor: '#007bff',
    buttonTextColor: '#ffffff',
  }

  try {
    // Try to fetch branding from the API
    const response = await fetch(`${API_BASE}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.DescribeManagedLoginBrandingByClient',
      },
      body: JSON.stringify({
        ClientId: clientId,
        UserPoolId: '', // Will be resolved by backend
      }),
    })

    if (!response.ok) {
      return defaultBranding
    }

    const data = await response.json()
    const branding = data.ManagedLoginBranding

    if (!branding) {
      return defaultBranding
    }

    const settings = branding.Settings || {}
    const colors = settings.Colors || {}
    const assets = branding.Assets || {}

    return {
      pageTitle: settings.PageTitle || defaultBranding.pageTitle,
      signInHeader: settings.SignInHeader || defaultBranding.signInHeader,
      signInSubheader: settings.SignInSubheader || defaultBranding.signInSubheader,
      backgroundColor: colors.BackgroundColor || defaultBranding.backgroundColor,
      primaryColor: colors.PrimaryColor || defaultBranding.primaryColor,
      textColor: colors.TextColor || defaultBranding.textColor,
      buttonColor: colors.ButtonColor || defaultBranding.buttonColor,
      buttonTextColor: colors.ButtonTextColor || defaultBranding.buttonTextColor,
      logoUrl: assets.LogoUrl,
    }
  } catch {
    return defaultBranding
  }
}

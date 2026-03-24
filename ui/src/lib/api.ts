import type { OAuthParams, Branding, UserPool, User, UserPoolClient, ManagedLoginBranding } from './types'

const API_BASE =
  typeof window !== 'undefined' && window.location.port === '9229'
    ? window.location.origin
    : 'http://localhost:9229'

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
      headers: {
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
    })

    const contentType = response.headers.get('content-type') || ''

    if (response.ok && contentType.includes('application/json')) {
      const data = await response.json()
      if (data.redirectUrl) {
        return { success: true, redirectUrl: data.redirectUrl }
      }
      return { success: false, error: data.error_description || data.error || 'Login failed' }
    }

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

// ============================================================================
// Admin API Functions
// ============================================================================

async function cognitoRequest<T>(action: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(`${API_BASE}/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': `AWSCognitoIdentityProviderService.${action}`,
    },
    body: JSON.stringify(body),
  })

  const data = await response.json()

  if (!response.ok) {
    throw new Error(data.message || data.__type || `${action} failed`)
  }

  return data
}

// User Pool Operations
export async function listUserPools(maxResults = 60): Promise<UserPool[]> {
  const data = await cognitoRequest<{ UserPools: UserPool[] }>('ListUserPools', {
    MaxResults: maxResults,
  })
  return data.UserPools || []
}

export async function createUserPool(poolName: string): Promise<UserPool> {
  const data = await cognitoRequest<{ UserPool: UserPool }>('CreateUserPool', {
    PoolName: poolName,
  })
  return data.UserPool
}

export async function describeUserPool(userPoolId: string): Promise<UserPool> {
  const data = await cognitoRequest<{ UserPool: UserPool }>('DescribeUserPool', {
    UserPoolId: userPoolId,
  })
  return data.UserPool
}

export async function deleteUserPool(userPoolId: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('DeleteUserPool', {
    UserPoolId: userPoolId,
  })
}

// User Operations
export async function listUsers(userPoolId: string): Promise<User[]> {
  const data = await cognitoRequest<{ Users: User[] }>('ListUsers', {
    UserPoolId: userPoolId,
  })
  return data.Users || []
}

export async function adminCreateUser(
  userPoolId: string,
  username: string,
  email: string,
  temporaryPassword?: string
): Promise<User> {
  const data = await cognitoRequest<{ User: User }>('AdminCreateUser', {
    UserPoolId: userPoolId,
    Username: username,
    UserAttributes: [{ Name: 'email', Value: email }],
    ...(temporaryPassword && { TemporaryPassword: temporaryPassword }),
  })
  return data.User
}

export async function adminGetUser(userPoolId: string, username: string): Promise<User> {
  const data = await cognitoRequest<User>('AdminGetUser', {
    UserPoolId: userPoolId,
    Username: username,
  })
  return data
}

export async function adminDeleteUser(userPoolId: string, username: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('AdminDeleteUser', {
    UserPoolId: userPoolId,
    Username: username,
  })
}

export async function adminEnableUser(userPoolId: string, username: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('AdminEnableUser', {
    UserPoolId: userPoolId,
    Username: username,
  })
}

export async function adminDisableUser(userPoolId: string, username: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('AdminDisableUser', {
    UserPoolId: userPoolId,
    Username: username,
  })
}

// User Pool Client Operations
export async function listUserPoolClients(userPoolId: string): Promise<UserPoolClient[]> {
  const data = await cognitoRequest<{ UserPoolClients: UserPoolClient[] }>('ListUserPoolClients', {
    UserPoolId: userPoolId,
    MaxResults: 60,
  })
  return data.UserPoolClients || []
}

export async function createUserPoolClient(
  userPoolId: string,
  clientName: string,
  callbackUrls?: string[],
  oauthFlows?: string[],
  oauthScopes?: string[]
): Promise<UserPoolClient> {
  const hasOAuthConfig =
    Boolean(callbackUrls && callbackUrls.length > 0) ||
    Boolean(oauthFlows && oauthFlows.length > 0) ||
    Boolean(oauthScopes && oauthScopes.length > 0)

  const data = await cognitoRequest<{ UserPoolClient: UserPoolClient }>('CreateUserPoolClient', {
    UserPoolId: userPoolId,
    ClientName: clientName,
    ...(callbackUrls && { CallbackURLs: callbackUrls }),
    ...(oauthFlows && { AllowedOAuthFlows: oauthFlows }),
    ...(oauthScopes && { AllowedOAuthScopes: oauthScopes }),
    ...(hasOAuthConfig && { AllowedOAuthFlowsUserPoolClient: true }),
  })
  return data.UserPoolClient
}

export async function describeUserPoolClient(
  userPoolId: string,
  clientId: string
): Promise<UserPoolClient> {
  const data = await cognitoRequest<{ UserPoolClient: UserPoolClient }>('DescribeUserPoolClient', {
    UserPoolId: userPoolId,
    ClientId: clientId,
  })
  return data.UserPoolClient
}

export async function deleteUserPoolClient(userPoolId: string, clientId: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('DeleteUserPoolClient', {
    UserPoolId: userPoolId,
    ClientId: clientId,
  })
}

// Domain Operations
export async function createUserPoolDomain(userPoolId: string, domain: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('CreateUserPoolDomain', {
    UserPoolId: userPoolId,
    Domain: domain,
  })
}

export async function deleteUserPoolDomain(userPoolId: string, domain: string): Promise<void> {
  await cognitoRequest<Record<string, never>>('DeleteUserPoolDomain', {
    UserPoolId: userPoolId,
    Domain: domain,
  })
}

// Branding Operations
export async function describeManagedLoginBranding(
  userPoolId: string,
  brandingId: string
): Promise<ManagedLoginBranding | null> {
  try {
    const data = await cognitoRequest<{ ManagedLoginBranding: ManagedLoginBranding }>(
      'DescribeManagedLoginBranding',
      { UserPoolId: userPoolId, ManagedLoginBrandingId: brandingId }
    )
    return data.ManagedLoginBranding
  } catch {
    return null
  }
}

export async function createManagedLoginBranding(
  userPoolId: string,
  clientId: string,
  settings?: Record<string, unknown>
): Promise<ManagedLoginBranding> {
  const data = await cognitoRequest<{ ManagedLoginBranding: ManagedLoginBranding }>(
    'CreateManagedLoginBranding',
    {
      UserPoolId: userPoolId,
      ClientId: clientId,
      UseCognitoProvidedValues: true,
      ...(settings && { Settings: settings }),
    }
  )
  return data.ManagedLoginBranding
}

export async function updateManagedLoginBranding(
  userPoolId: string,
  brandingId: string,
  settings: Record<string, unknown>
): Promise<ManagedLoginBranding> {
  const data = await cognitoRequest<{ ManagedLoginBranding: ManagedLoginBranding }>(
    'UpdateManagedLoginBranding',
    {
      UserPoolId: userPoolId,
      ManagedLoginBrandingId: brandingId,
      Settings: settings,
    }
  )
  return data.ManagedLoginBranding
}

export async function deleteManagedLoginBranding(
  userPoolId: string,
  brandingId: string
): Promise<void> {
  await cognitoRequest<Record<string, never>>('DeleteManagedLoginBranding', {
    UserPoolId: userPoolId,
    ManagedLoginBrandingId: brandingId,
  })
}

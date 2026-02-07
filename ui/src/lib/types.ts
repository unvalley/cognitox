export interface OAuthParams {
  response_type: string
  client_id: string
  redirect_uri: string
  scope?: string
  state?: string
  nonce?: string
  code_challenge?: string
  code_challenge_method?: string
}

export interface Branding {
  pageTitle: string
  signInHeader: string
  signInSubheader: string
  backgroundColor: string
  primaryColor: string
  textColor: string
  buttonColor: string
  buttonTextColor: string
  logoUrl?: string
}

export type Page = 'login' | 'signup' | 'confirm' | 'forgot-password' | 'reset-password'

export interface AppState {
  page: Page
  oauth: OAuthParams
  branding: Branding
  error?: string
  success?: string
  username?: string
}

// Admin UI Types
export interface UserPool {
  Id: string
  Name: string
  CreationDate: string
  LastModifiedDate: string
  Status?: string
  Domain?: string
  CustomDomain?: string
  MfaConfiguration?: string
}

export interface User {
  Username: string
  UserStatus: string
  Enabled: boolean
  UserCreateDate: string
  UserLastModifiedDate: string
  Attributes: UserAttribute[]
}

export interface UserAttribute {
  Name: string
  Value: string
}

export interface UserPoolClient {
  ClientId: string
  ClientName: string
  UserPoolId: string
  CreationDate?: string
  LastModifiedDate?: string
  AllowedOAuthFlows?: string[]
  AllowedOAuthScopes?: string[]
  CallbackURLs?: string[]
  LogoutURLs?: string[]
  ExplicitAuthFlows?: string[]
}

export interface ManagedLoginBranding {
  ManagedLoginBrandingId: string
  UserPoolId: string
  UseCognitoProvidedValues?: boolean
  Settings?: Record<string, unknown>
  Assets?: Record<string, unknown>
}

export type AdminPage =
  | 'dashboard'
  | 'user-pools'
  | 'user-pool-detail'
  | 'users'
  | 'user-detail'
  | 'clients'
  | 'client-detail'
  | 'branding'

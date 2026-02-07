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

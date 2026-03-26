import type { ComponentChildren } from 'preact'
import type { Branding } from './types'

interface Props {
  branding: Branding
  children: ComponentChildren
}

export function Card({ branding, children }: Props) {
  return (
    <div class="card bg-base-100 shadow-lg w-full max-w-md">
      <div class="card-body">
        {branding.logoUrl && (
          <div class="text-center mb-4">
            <img src={branding.logoUrl} alt="Logo" class="max-w-36 max-h-15 mx-auto" />
          </div>
        )}
        {children}
      </div>
    </div>
  )
}

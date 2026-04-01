import type { ComponentChildren } from 'preact'
import type { Branding } from './types'

interface Props {
  branding: Branding
  children: ComponentChildren
}

export function Card({ branding, children }: Props) {
  return (
    <div class="card bg-base-100 shadow-xl w-full max-w-md border border-base-200/50">
      <div class="card-body p-8">
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

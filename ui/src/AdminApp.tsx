import { UserPoolList } from './admin/UserPoolList'

function AdminLayout() {
  return (
    <div class="admin-shell flex min-h-screen flex-col">
      <header class="bg-white">
        <div class="px-4 py-4 sm:px-6">
          <div class="mx-auto flex max-w-7xl items-center justify-between gap-3">
            <div class="flex items-center">
              <img src="/ui/icon-192-rounded.png" alt="Cognitox" class="h-10 w-10 rounded-xl" />
            </div>

            <div class="flex items-center gap-5">
              <a
                class="text-sm text-slate-500 hover:text-slate-900"
                href="https://github.com/unvalley/cognitox"
                target="_blank"
                rel="noopener noreferrer"
              >
                Docs
              </a>
              <button class="btn btn-sm" onClick={() => { window.location.href = '/ui/' }}>Hosted UI</button>
            </div>
          </div>
        </div>
      </header>

      <main class="flex-1 bg-white px-4 py-4 sm:px-6 sm:py-6">
        <div class="mx-auto max-w-7xl">
          <UserPoolList />
        </div>
      </main>

      <footer class="px-4 pb-4 pt-2 sm:px-6 sm:pb-6">
        <div class="mx-auto max-w-7xl text-center text-sm text-slate-500">
          <a
            class="btn btn-link btn-sm px-0 text-slate-500 no-underline hover:no-underline"
            href="https://github.com/unvalley/cognitox"
            target="_blank"
            rel="noopener noreferrer"
          >
            github.com/unvalley/cognitox
          </a>
        </div>
      </footer>
    </div>
  )
}

export function AdminApp() {
  return <AdminLayout />
}

import './app.css'
import './admin.css'
import { render } from 'preact'
import { LocationProvider, Route, Router } from 'preact-iso'
import { HostedUiApp } from './App'
import { AdminApp } from './AdminApp'

function RootApp() {
  return (
    <LocationProvider>
      <Router>
        <Route path="/admin" component={AdminApp} />
        <Route path="/admin/{*path}" component={AdminApp} />
        <Route default component={HostedUiApp} />
      </Router>
    </LocationProvider>
  )
}

render(<RootApp />, document.getElementById('app')!)

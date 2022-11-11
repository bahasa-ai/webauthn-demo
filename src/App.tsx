import { MantineProvider } from '@mantine/core'
import { NotificationsProvider } from '@mantine/notifications'
import { Route, Routes } from 'react-router-dom'
import Home from './pages/Home'
import Passkey from './pages/Passkey'

import './App.css'

function App() {
  return <MantineProvider withGlobalStyles withNormalizeCSS>
    <NotificationsProvider>
      <div style={{ minHeight: 'calc(100vh - 160px)', position: 'relative' }}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/passkey" element={<Passkey />} />
        </Routes>
      </div>
    </NotificationsProvider>
  </MantineProvider>
}

export default App

import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// No StrictMode — prevents double-mount which creates duplicate WS connections
ReactDOM.createRoot(document.getElementById('root')!).render(
  <App />
)

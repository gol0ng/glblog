import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import Post from './pages/Post'
import Login from './pages/admin/Login'
import Dashboard from './pages/admin/Dashboard'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/post/:slug" element={<Post />} />
        <Route path="/admin" element={<Dashboard />} />
        <Route path="/admin/login" element={<Login />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App

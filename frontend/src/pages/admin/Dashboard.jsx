import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkMath from 'remark-math'
import rehypeKatex from 'rehype-katex'
import 'katex/dist/katex.min.css'

function Dashboard() {
  const [posts, setPosts] = useState([])
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(null)
  const [title, setTitle] = useState('')
  const [slug, setSlug] = useState('')
  const [date, setDate] = useState('')
  const [body, setBody] = useState('')
  const [message, setMessage] = useState('')
  const [uploading, setUploading] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    const token = localStorage.getItem('admin_token')
    if (!token) {
      navigate('/admin/login')
      return
    }
    loadPosts()
  }, [])

  const loadPosts = async () => {
    try {
      const res = await fetch('/api/admin/posts')
      const data = await res.json()
      setPosts(data)
    } finally {
      setLoading(false)
    }
  }

  const handleCreate = () => {
    setEditing({ isNew: true })
    setTitle('')
    setSlug('')
    setDate(new Date().toISOString().split('T')[0])
    setBody('')
  }

  const handleEdit = (post) => {
    setEditing(post)
    setTitle(post.title)
    setSlug(post.slug)
    setDate(post.date)
    setBody(post.body)
  }

  const handleSave = async () => {
    const post = { title, slug, date, body }
    const method = editing.isNew ? 'POST' : 'PUT'
    const url = editing.isNew ? '/api/admin/posts' : `/api/admin/posts/${editing.slug}`

    try {
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(post)
      })
      if (res.ok) {
        setMessage(editing.isNew ? 'Post created!' : 'Post updated!')
        setEditing(null)
        loadPosts()
      } else {
        setMessage('Failed to save post')
      }
    } catch {
      setMessage('Failed to save post')
    }
  }

  const handleDelete = async (slug) => {
    if (!confirm('Delete this post?')) return
    try {
      const res = await fetch(`/api/admin/posts/${slug}`, { method: 'DELETE' })
      if (res.ok) {
        setMessage('Post deleted!')
        loadPosts()
      }
    } catch {
      setMessage('Failed to delete post')
    }
  }

  const handleCancel = () => {
    setEditing(null)
    setMessage('')
  }

  const handleLogout = () => {
    localStorage.removeItem('admin_token')
    navigate('/')
  }

  const handleUpload = async (e) => {
    const file = e.target.files[0]
    if (!file) return

    setUploading(true)
    const formData = new FormData()
    formData.append('image', file)

    try {
      const res = await fetch('/api/admin/upload', {
        method: 'POST',
        body: formData
      })
      const data = await res.json()
      if (data.url) {
        setBody(body + `\n![${file.name}](${data.url})\n`)
      } else {
        setMessage('Upload failed')
      }
    } catch {
      setMessage('Upload failed')
    }
    setUploading(false)
  }

  if (loading) {
    return <div className="admin-container"><p>Loading...</p></div>
  }

  if (editing) {
    return (
      <div className="editor-wrapper">
        <div className="editor-header">
          <h1>{editing.isNew ? 'New Post' : 'Edit Post'}</h1>
        </div>
        {message && <p className={message.includes('Failed') ? 'error' : 'success'}>{message}</p>}
        <div className="editor-form">
          <div className="editor-row">
            <input
              type="text"
              placeholder="Title"
              value={title}
              onChange={e => setTitle(e.target.value)}
            />
            <input
              type="text"
              placeholder="Slug (URL-friendly)"
              value={slug}
              onChange={e => setSlug(e.target.value)}
            />
          </div>
          <div className="editor-content">
            <textarea
              className="editor-textarea"
              placeholder="Write your post content in Markdown..."
              value={body}
              onChange={e => setBody(e.target.value)}
            />
            <div className="editor-preview post-body">
              <ReactMarkdown remarkPlugins={[remarkMath]} rehypePlugins={[rehypeKatex]}>{body}</ReactMarkdown>
            </div>
          </div>
          <div className="editor-footer">
            <label className="btn btn-secondary" style={{ cursor: 'pointer' }}>
              {uploading ? 'Uploading...' : 'Upload Image'}
              <input
                type="file"
                accept="image/*"
                onChange={handleUpload}
                style={{ display: 'none' }}
              />
            </label>
            <button className="btn" onClick={handleSave}>Save</button>
            <button className="btn btn-secondary" onClick={handleCancel}>Cancel</button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="admin-container">
      <div className="admin-header">
        <h1>Dashboard</h1>
        <div className="admin-nav">
          <Link to="/">View Blog</Link>
          <button className="btn btn-secondary" onClick={handleLogout}>Logout</button>
        </div>
      </div>
      {message && <p className={message.includes('Failed') ? 'error' : 'success'}>{message}</p>}
      <div className="actions">
        <button className="btn" onClick={handleCreate}>New Post</button>
      </div>
      <table className="admin-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Date</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {posts.map(post => (
            <tr key={post.slug}>
              <td className="admin-title">{post.title}</td>
              <td className="admin-date">{post.date}</td>
              <td className="admin-actions">
                <button className="btn btn-secondary" onClick={() => handleEdit(post)}>Edit</button>
                <button className="btn btn-danger" onClick={() => handleDelete(post.slug)}>Delete</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default Dashboard
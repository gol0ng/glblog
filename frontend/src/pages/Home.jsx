import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function Home() {
  const [posts, setPosts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/posts')
      .then(res => res.json())
      .then(data => {
        setPosts(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  return (
    <div className="container">
      <header>
        <h1><Link to="/">golong's blog</Link></h1>
      </header>
      {loading ? (
        <p>Loading...</p>
      ) : posts.length === 0 ? (
        <p>No posts yet.</p>
      ) : (
        <ul className="post-list">
          {posts.map(post => (
            <li key={post.slug}>
              <h2>
                <Link to={`/post/${post.slug}`}>{post.title}</Link>
              </h2>
              <span className="date">{post.date}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default Home

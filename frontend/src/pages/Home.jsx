import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function Home() {
  const [posts, setPosts] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [isSearching, setIsSearching] = useState(false)

  useEffect(() => {
    fetch('/api/posts')
      .then(res => res.json())
      .then(data => {
        setPosts(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!searchQuery.trim()) return

    setIsSearching(true)
    try {
      const res = await fetch(`/api/search?q=${encodeURIComponent(searchQuery)}`)
      const data = await res.json()
      setSearchResults(data)
    } finally {
      setIsSearching(false)
    }
  }

  const clearSearch = () => {
    setSearchQuery('')
    setSearchResults([])
  }

  const displayPosts = searchResults.length > 0 ? searchResults : posts
  const isSearchMode = searchResults.length > 0

  return (
    <div className="container">
      <header>
        <h1><Link to="/">golong's blog</Link></h1>
      </header>

      <div className="search-section">
        <form onSubmit={handleSearch} className="search-form">
          <input
            type="text"
            placeholder="Search posts..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="search-input"
          />
          <button type="submit" className="btn" disabled={isSearching}>
            {isSearching ? 'Searching...' : 'Search'}
          </button>
          {isSearchMode && (
            <button type="button" className="btn btn-secondary" onClick={clearSearch}>
              Clear
            </button>
          )}
        </form>
      </div>

      {isSearchMode && (
        <p className="search-info">
          Found {searchResults.length} result(s) for "{searchQuery}"
        </p>
      )}

      <footer className="home-footer">
        <div className="social-links">
          <a href="https://space.bilibili.com/你的B站ID" target="_blank" rel="noopener noreferrer">B站</a>
          <a href="https://www.douyin.com/你的抖音ID" target="_blank" rel="noopener noreferrer">抖音</a>
          <a href="https://www.zhihu.com/people/你的知乎ID" target="_blank" rel="noopener noreferrer">知乎</a>
        </div>
      </footer>

      {loading ? (
        <p>Loading...</p>
      ) : displayPosts.length === 0 ? (
        <p>No posts yet.</p>
      ) : (
        <ul className="post-list">
          {displayPosts.map(post => (
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
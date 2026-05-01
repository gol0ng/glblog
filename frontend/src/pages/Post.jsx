import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkMath from 'remark-math'
import rehypeKatex from 'rehype-katex'
import 'katex/dist/katex.min.css'

function Post() {
  const { slug } = useParams()
  const [post, setPost] = useState(null)
  const [loading, setLoading] = useState(true)
  const [headings, setHeadings] = useState([])

  useEffect(() => {
    fetch(`/api/posts/${slug}`)
      .then(res => res.json())
      .then(data => {
        setPost(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [slug])

  useEffect(() => {
    if (post?.body) {
      // Extract h2 headings
      const matches = post.body.match(/^## (.+)$/gm)
      if (matches) {
        const unique = [...new Set(matches)]
        setHeadings(unique)
      }
    }
  }, [post])

  if (loading) {
    return <div className="container"><p>Loading...</p></div>
  }

  if (!post) {
    return (
      <div className="container">
        <p>Post not found.</p>
        <Link to="/">Back to home</Link>
      </div>
    )
  }

  return (
    <div className="post-container">
      <header>
        <h1><Link to="/">golong's blog</Link></h1>
      </header>
      <div className="post-layout">
        <article className="post-content">
          <h2>{post.title}</h2>
          <p className="post-meta">{post.date}</p>
          <div className="post-body">
            <ReactMarkdown remarkPlugins={[remarkMath]} rehypePlugins={[rehypeKatex]}>{post.body}</ReactMarkdown>
          </div>
        </article>
        {headings.length > 0 && (
          <aside className="post-toc">
            <h3>Table of Contents</h3>
            <ul>
              {headings.map((heading, i) => {
                const text = heading.replace(/^## /, '')
                const id = text.toLowerCase().replace(/\s+/g, '-')
                return (
                  <li key={i}>
                    <a href={`#${id}`}>{text}</a>
                  </li>
                )
              })}
            </ul>
          </aside>
        )}
      </div>
    </div>
  )
}

export default Post
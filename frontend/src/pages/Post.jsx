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

  useEffect(() => {
    fetch(`/api/posts/${slug}`)
      .then(res => res.json())
      .then(data => {
        setPost(data)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [slug])

  if (loading) {
    return (
      <div className="container">
        <p>Loading...</p>
      </div>
    )
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
    <div className="container">
      <header>
        <h1><Link to="/">golong's blog</Link></h1>
      </header>
      <article>
        <h2>{post.title}</h2>
        <p className="post-meta">{post.date}</p>
        <div className="post-body">
          <ReactMarkdown remarkPlugins={[remarkMath]} rehypePlugins={[rehypeKatex]}>{post.body}</ReactMarkdown>
        </div>
      </article>
    </div>
  )
}

export default Post

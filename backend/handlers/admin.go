package handlers

import (
	"blog/models"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

var adminPassword = "admin123"

func Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	h := sha256.Sum256([]byte(req.Password))
	if req.Username == "admin" && base64.StdEncoding.EncodeToString(h[:]) == "JAvlGPq9JyTdtvBO6x2llnRI1+gxwIyPqCKAn3THIKk=" {
		c.JSON(http.StatusOK, gin.H{"token": "authenticated"})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func GetAdminPosts(c *gin.Context) {
	posts, err := loadPosts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load posts"})
		return
	}
	c.JSON(http.StatusOK, posts)
}

func CreatePost(c *gin.Context) {
	var post models.Post
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	content := "---\ntitle: " + post.Title + "\ndate: " + post.Date + "\n---\n" + post.Body
	filePath := filepath.Join("posts", post.Slug+".md")
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post"})
		return
	}

	c.JSON(http.StatusCreated, post)
}

func UpdatePost(c *gin.Context) {
	slug := c.Param("slug")
	var post models.Post
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	oldPath := filepath.Join("posts", slug+".md")
	newPath := filepath.Join("posts", post.Slug+".md")

	if slug != post.Slug {
		os.Rename(oldPath, newPath)
	} else {
		os.Remove(oldPath)
	}

	content := "---\ntitle: " + post.Title + "\ndate: " + post.Date + "\n---\n" + post.Body
	if err := os.WriteFile(newPath, []byte(content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update post"})
		return
	}

	c.JSON(http.StatusOK, post)
}

func DeletePost(c *gin.Context) {
	slug := c.Param("slug")
	filePath := filepath.Join("posts", slug+".md")
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete post"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Post deleted"})
}

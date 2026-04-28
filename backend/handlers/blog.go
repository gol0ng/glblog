package handlers

import (
	"blog/models"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetPosts(c *gin.Context) {
	posts, err := loadPosts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load posts"})
		return
	}
	c.JSON(http.StatusOK, posts)
}

func GetPost(c *gin.Context) {
	slug := c.Param("slug")
	post, err := loadPost(slug)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Post not found"})
		return
	}
	c.JSON(http.StatusOK, post)
}

func loadPosts() ([]models.Post, error) {
	postsDir := "posts"
	entries, err := os.ReadDir(postsDir)
	if err != nil {
		return nil, err
	}

	var posts []models.Post
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		slug := strings.TrimSuffix(entry.Name(), ".md")
		post, err := loadPost(slug)
		if err != nil {
			continue
		}
		posts = append(posts, post)
	}

	sort.Slice(posts, func(i, j int) bool {
		return posts[i].Date > posts[j].Date
	})

	return posts, nil
}

func loadPost(slug string) (models.Post, error) {
	filePath := filepath.Join("posts", slug+".md")
	content, err := os.ReadFile(filePath)
	if err != nil {
		return models.Post{}, err
	}

	lines := strings.Split(string(content), "\n")
	var title, date string
	var bodyLines []string
	inBody := false

	for _, line := range lines {
		if strings.HasPrefix(line, "title: ") {
			title = strings.TrimPrefix(line, "title: ")
		} else if strings.HasPrefix(line, "date: ") {
			date = strings.TrimPrefix(line, "date: ")
		} else if strings.TrimSpace(line) == "---" {
			if title != "" && date != "" {
				inBody = true
			}
		} else if inBody {
			bodyLines = append(bodyLines, line)
		}
	}

	return models.Post{
		Slug:  slug,
		Title: title,
		Date:  date,
		Body:  strings.Join(bodyLines, "\n"),
	}, nil
}

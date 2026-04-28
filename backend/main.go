package main

import (
	"blog/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// API routes
	api := r.Group("/api")
	{
		api.GET("/posts", handlers.GetPosts)
		api.GET("/posts/:slug", handlers.GetPost)

		admin := api.Group("/admin")
		{
			admin.POST("/login", handlers.Login)
			admin.GET("/posts", handlers.GetAdminPosts)
			admin.POST("/posts", handlers.CreatePost)
			admin.PUT("/posts/:slug", handlers.UpdatePost)
			admin.DELETE("/posts/:slug", handlers.DeletePost)
		}
	}

	r.Run(":8080")
}

package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/qiniu/go-sdk/v7/auth"
	"github.com/qiniu/go-sdk/v7/storage"
)

var (
	qiniuAccessKey = os.Getenv("QINIU_ACCESS_KEY")
	qiniuSecretKey = os.Getenv("QINIU_SECRET_KEY")
	qiniuBucket    = os.Getenv("QINIU_BUCKET")
	qiniuDomain    = os.Getenv("QINIU_DOMAIN")
)

func UploadImage(c *gin.Context) {
	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No image provided"})
		return
	}

	if qiniuAccessKey == "" || qiniuSecretKey == "" || qiniuBucket == "" || qiniuDomain == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Qiniu not configured"})
		return
	}

	ext := filepath.Ext(file.Filename)
	timestamp := time.Now().Unix()
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	filename := fmt.Sprintf("%d_%s%s", timestamp, hex.EncodeToString(randBytes), ext)

	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	defer f.Close()

	putPolicy := storage.PutPolicy{
		Scope: qiniuBucket,
	}
	mac := auth.New(qiniuAccessKey, qiniuSecretKey)
	upToken := putPolicy.UploadToken(mac)

	cfg := storage.Config{
		Region: &storage.ZoneHuadong,
	}
	formUploader := storage.NewFormUploader(&cfg)
	ret := storage.PutRet{}

	err = formUploader.Put(c.Request.Context(), &ret, upToken, filename, f, file.Size, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Upload failed: " + err.Error()})
		return
	}

	url := fmt.Sprintf("https://%s/%s", qiniuDomain, ret.Key)
	c.JSON(http.StatusOK, gin.H{"url": url})
}
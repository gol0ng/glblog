package models

type Post struct {
	Slug  string `json:"slug"`
	Title string `json:"title"`
	Date  string `json:"date"`
	Body  string `json:"body"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

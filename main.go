package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	
    "github.com/joho/godotenv"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	DB        *sql.DB
	JWTSecret []byte
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type Blog struct {
	ID          int    `json:"id"`
	Slug        string `json:"slug"`
	Title       string `json:"title"`
	TitleEN     string `json:"title_en"`
	Description string `json:"description"`
	DescEN      string `json:"desc_en"`
	Content     string `json:"content"`
	ContentEN   string `json:"content_en"`
	Image       string `json:"image"`
	Category    string `json:"category"`
	CategoryEN  string `json:"category_en"`
	ReadTime    string `json:"read_time"`
	ShowHome    bool   `json:"show_home"`
	CreatedAt   string `json:"created_at"`
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// ── Email Config ─────────────────────────────────────────────────────────────
func sendResetEmail(toEmail, resetToken, frontendURL string) error {
	host     := getEnv("SMTP_HOST", "smtp.gmail.com")
	port     := getEnv("SMTP_PORT", "587")
	username := getEnv("SMTP_USER", "")
	password := getEnv("SMTP_PASS", "")
	from     := getEnv("SMTP_FROM", username)

	if username == "" || password == "" {
		log.Println("⚠️  SMTP tidak dikonfigurasi, skip kirim email")
		return nil
	}

	resetLink := fmt.Sprintf("%s/forgot-password?token=%s", frontendURL, resetToken)
	subject   := "Reset Password Portfolio"

	body := "<html><body style=\"font-family:Arial,sans-serif;background:#030712;margin:0;padding:32px\">" +
		"<div style=\"max-width:480px;margin:0 auto;background:#0f172a;border-radius:20px;padding:40px;border:1px solid #1e293b\">" +
		"<div style=\"text-align:center;margin-bottom:32px\">" +
		"<h1 style=\"margin:0;font-size:28px;font-weight:900;background:linear-gradient(135deg,#a78bfa,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent\">Portfolio</h1>" +
		"</div>" +
		"<h2 style=\"color:#e2e8f0;font-size:20px;margin:0 0 12px\">🔐 Reset Password</h2>" +
		"<p style=\"color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 28px\">Kamu menerima email ini karena ada permintaan reset password untuk akun kamu. Klik tombol di bawah untuk membuat password baru.</p>" +
		"<div style=\"text-align:center;margin:0 0 28px\">" +
		"<a href=\"" + resetLink + "\" style=\"display:inline-block;padding:14px 32px;background:#1e1e1e;color:#e2e8f0;text-decoration:none;border-radius:6px;font-weight:500;font-size:14px;letter-spacing:0.2px;border:1px solid #3d3d3d;font-family:monospace\">Reset Password Sekarang</a>" +
		"</div>" +
		"<div style=\"background:#1e293b;border-radius:10px;padding:14px 16px;margin-bottom:24px\">" +
		"<p style=\"color:#64748b;font-size:11px;margin:0 0 6px\">Atau copy link ini ke browser:</p>" +
		"<p style=\"color:#a78bfa;font-size:12px;word-break:break-all;margin:0\">" + resetLink + "</p>" +
		"</div>" +
		"<p style=\"color:#475569;font-size:12px;text-align:center;margin:0\"><strong style=\"color:#94a3b8\">Link berlaku selama 1 jam.</strong><br>Abaikan email ini jika kamu tidak merasa meminta reset password.</p>" +
		"</div></body></html>"

	headers := "To: " + toEmail + "\r\n" +
		"From: Portfolio <" + from + ">\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n"

	msg := []byte(headers + body)

	addr := fmt.Sprintf("%s:%s", host, port)
	var sendErr error
	if port == "465" {
		// SSL/TLS langsung
		tlsConf := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", addr, tlsConf)
		if err != nil {
			log.Printf("❌ Gagal koneksi TLS ke %s: %v", addr, err)
			return err
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, host)
		if err != nil { return err }
		auth := smtp.PlainAuth("", username, password, host)
		if err = client.Auth(auth); err != nil { return err }
		if err = client.Mail(from); err != nil { return err }
		if err = client.Rcpt(toEmail); err != nil { return err }
		w, err := client.Data()
		if err != nil { return err }
		_, sendErr = w.Write(msg)
		w.Close()
		client.Quit()
	} else {
		// STARTTLS (587) atau plaintext
		auth := smtp.PlainAuth("", username, password, host)
		sendErr = smtp.SendMail(addr, auth, from, []string{toEmail}, msg)
	}
	if sendErr != nil {
		log.Printf("❌ Gagal kirim email ke %s: %v", toEmail, sendErr)
		return sendErr
	}
	log.Printf("✅ Email reset terkirim ke %s", toEmail)
	return nil
}

func initDB() {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		getEnv("DB_USER", "root"),
		getEnv("DB_PASS", "thelegendaryisp"),
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "3306"),
		getEnv("DB_NAME", "portofolio_db"),
	)

	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Gagal koneksi DB:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("DB tidak bisa diping:", err)
	}

	createTables()
	seedMasterAdmin()
	log.Println("✅ Database terhubung")
}

func createTables() {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id         INT AUTO_INCREMENT PRIMARY KEY,
			username   VARCHAR(50)  UNIQUE NOT NULL,
			email      VARCHAR(100) UNIQUE NOT NULL,
			password   VARCHAR(255) NOT NULL,
			role       ENUM('user','admin','master_admin') DEFAULT 'user',
			reset_token VARCHAR(64)  DEFAULT NULL,
			reset_exp   DATETIME     DEFAULT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS blogs (
			id          INT AUTO_INCREMENT PRIMARY KEY,
			slug        VARCHAR(255) UNIQUE DEFAULT NULL,
			title       VARCHAR(255) NOT NULL,
			title_en    VARCHAR(255) NOT NULL DEFAULT '',
			description TEXT,
			desc_en     TEXT,
			content     LONGTEXT,
			content_en  LONGTEXT,
			image       LONGTEXT,
			category    VARCHAR(100),
			category_en VARCHAR(100),
			read_time   VARCHAR(20) DEFAULT '3 min',
			show_home   TINYINT(1)  DEFAULT 0,
			created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, q := range queries {
		if _, err := DB.Exec(q); err != nil {
			log.Fatal("Gagal buat tabel:", err)
		}
	}

	// Migrasi aman: tambah kolom slug jika belum ada (kompatibel semua versi MySQL)
	var colCount int
	DB.QueryRow(`SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='blogs' AND COLUMN_NAME='slug'`).Scan(&colCount)
	if colCount == 0 {
		if _, err := DB.Exec(`ALTER TABLE blogs ADD COLUMN slug VARCHAR(255) UNIQUE DEFAULT NULL`); err != nil {
			log.Println("⚠️  Gagal tambah kolom slug:", err)
		} else {
			log.Println("✅ Kolom slug berhasil ditambahkan")
		}
	}

	// Migrasi: pastikan kolom image cukup besar untuk base64
	var imageColType string
	DB.QueryRow(`SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='blogs' AND COLUMN_NAME='image'`).Scan(&imageColType)
	if imageColType == "varchar" {
		if _, err := DB.Exec(`ALTER TABLE blogs MODIFY COLUMN image LONGTEXT`); err != nil {
			log.Println("⚠️  Gagal migrate kolom image:", err)
		} else {
			log.Println("✅ Kolom image diupgrade ke LONGTEXT")
		}
	}
}

func seedMasterAdmin() {
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM users WHERE role='master_admin'").Scan(&count)
	if count > 0 {
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("masteradmin123"), bcrypt.DefaultCost)
	DB.Exec(`INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)`,
		"masteradmin", "master@portfolio.com", string(hash), "master_admin")
	log.Println("✅ Master admin dibuat: masteradmin / masteradmin123")
}

func getEnvOrFatal(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("❌ Environment variable %s wajib diisi", key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateToken(user User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(JWTSecret)
}

func parseToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token tidak valid")
	}
	return token.Claims.(*Claims), nil
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token diperlukan"})
			c.Abort()
			return
		}
		claims, err := parseToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid"})
			c.Abort()
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func RoleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := c.MustGet("claims").(*Claims)
		for _, r := range roles {
			if claims.Role == r {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak"})
		c.Abort()
	}
}

func Register(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Email == "" || body.Password == "" {
		c.JSON(400, gin.H{"error": "Data tidak lengkap"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	_, err := DB.Exec(`INSERT INTO users (username,email,password,role) VALUES (?,?,?,'user')`,
		body.Username, body.Email, string(hash))
	if err != nil {
		c.JSON(400, gin.H{"error": "Username atau email sudah terdaftar"})
		return
	}
	c.JSON(200, gin.H{"message": "Registrasi berhasil"})
}

func Login(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Data tidak valid"})
		return
	}
	var u User
	var hash string
	err := DB.QueryRow(`SELECT id,username,email,role,password FROM users WHERE username=?`, body.Username).
		Scan(&u.ID, &u.Username, &u.Email, &u.Role, &hash)
	if err != nil {
		c.JSON(401, gin.H{"error": "Username atau password salah"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		c.JSON(401, gin.H{"error": "Username atau password salah"})
		return
	}
	token, _ := generateToken(u)
	c.JSON(200, gin.H{"token": token, "user": u})
}

func ForgotPassword(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Email == "" {
		c.JSON(400, gin.H{"error": "Username dan email wajib diisi"})
		return
	}

	// Normalize: lowercase + trim spasi
	inputEmail    := strings.ToLower(strings.TrimSpace(body.Email))
	inputUsername := strings.TrimSpace(body.Username)

	// Cari berdasarkan username dulu
	var id int
	var dbEmail string
	err := DB.QueryRow(`SELECT id, email FROM users WHERE username=?`, inputUsername).Scan(&id, &dbEmail)
	if err != nil {
		// Jangan bocorkan info apakah username ada atau tidak
		c.JSON(400, gin.H{"error": "Username atau email tidak sesuai"})
		return
	}

	// Bandingkan email (lowercase)
	if strings.ToLower(strings.TrimSpace(dbEmail)) != inputEmail {
		c.JSON(400, gin.H{"error": "Username atau email tidak sesuai"})
		return
	}

	token := randomString(32)
	exp := time.Now().Add(1 * time.Hour)
	DB.Exec(`UPDATE users SET reset_token=?, reset_exp=? WHERE id=?`, token, exp, id)

	frontendURL := getEnv("FRONTEND_URL", "http://localhost:5173")
	go sendResetEmail(dbEmail, token, frontendURL)

	c.JSON(200, gin.H{"message": "Link reset password sudah dikirim ke email kamu"})
}

func ResetPassword(c *gin.Context) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Token == "" || body.Password == "" {
		c.JSON(400, gin.H{"error": "Data tidak valid"})
		return
	}
	var id int
	var exp time.Time
	err := DB.QueryRow(`SELECT id,reset_exp FROM users WHERE reset_token=?`, body.Token).Scan(&id, &exp)
	if err != nil || time.Now().After(exp) {
		c.JSON(400, gin.H{"error": "Token tidak valid atau sudah kadaluarsa"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	DB.Exec(`UPDATE users SET password=?, reset_token=NULL, reset_exp=NULL WHERE id=?`, string(hash), id)
	c.JSON(200, gin.H{"message": "Password berhasil diubah"})
}

func GetMe(c *gin.Context) {
	claims := c.MustGet("claims").(*Claims)
	var u User
	DB.QueryRow(`SELECT id,username,email,role FROM users WHERE id=?`, claims.UserID).
		Scan(&u.ID, &u.Username, &u.Email, &u.Role)
	c.JSON(200, u)
}

func GetBlogs(c *gin.Context) {
	rows, err := DB.Query(`SELECT id,COALESCE(slug,''),title,title_en,description,desc_en,content,content_en,image,category,category_en,read_time,show_home,created_at FROM blogs ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal ambil data"})
		return
	}
	defer rows.Close()
	var blogs []Blog
	for rows.Next() {
		var b Blog
		rows.Scan(&b.ID, &b.Slug, &b.Title, &b.TitleEN, &b.Description, &b.DescEN, &b.Content, &b.ContentEN, &b.Image, &b.Category, &b.CategoryEN, &b.ReadTime, &b.ShowHome, &b.CreatedAt)
		blogs = append(blogs, b)
	}
	if blogs == nil {
		blogs = []Blog{}
	}
	c.JSON(200, blogs)
}

func GetHomeBlogs(c *gin.Context) {
	rows, err := DB.Query(`SELECT id,COALESCE(slug,''),title,title_en,description,desc_en,image,category,category_en,read_time,show_home,created_at FROM blogs WHERE show_home=1 ORDER BY created_at DESC LIMIT 3`)
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal ambil data"})
		return
	}
	defer rows.Close()
	var blogs []Blog
	for rows.Next() {
		var b Blog
		rows.Scan(&b.ID, &b.Slug, &b.Title, &b.TitleEN, &b.Description, &b.DescEN, &b.Image, &b.Category, &b.CategoryEN, &b.ReadTime, &b.ShowHome, &b.CreatedAt)
		blogs = append(blogs, b)
	}
	if blogs == nil {
		blogs = []Blog{}
	}
	c.JSON(200, blogs)
}

// GetBlogByID: cari by slug dulu, fallback ke id jika tidak ketemu
func GetBlogByID(c *gin.Context) {
	param := c.Param("id")
	var b Blog

	// Coba by slug dulu
	err := DB.QueryRow(`SELECT id,COALESCE(slug,''),title,title_en,description,desc_en,content,content_en,image,category,category_en,read_time,show_home,created_at FROM blogs WHERE slug=?`, param).
		Scan(&b.ID, &b.Slug, &b.Title, &b.TitleEN, &b.Description, &b.DescEN, &b.Content, &b.ContentEN, &b.Image, &b.Category, &b.CategoryEN, &b.ReadTime, &b.ShowHome, &b.CreatedAt)

	// Fallback by id
	if err != nil {
		err = DB.QueryRow(`SELECT id,COALESCE(slug,''),title,title_en,description,desc_en,content,content_en,image,category,category_en,read_time,show_home,created_at FROM blogs WHERE id=?`, param).
			Scan(&b.ID, &b.Slug, &b.Title, &b.TitleEN, &b.Description, &b.DescEN, &b.Content, &b.ContentEN, &b.Image, &b.Category, &b.CategoryEN, &b.ReadTime, &b.ShowHome, &b.CreatedAt)
		if err != nil {
			c.JSON(404, gin.H{"error": "Blog tidak ditemukan"})
			return
		}
	}
	c.JSON(200, b)
}

func CreateBlog(c *gin.Context) {
	var b Blog
	if err := c.ShouldBindJSON(&b); err != nil || b.Title == "" {
		c.JSON(400, gin.H{"error": "Data tidak lengkap"})
		return
	}
	if b.ShowHome {
		enforceHomeLimit(0)
	}
	// Slug kosong → simpan NULL agar tidak bentrok UNIQUE
	var slugVal interface{}
	if b.Slug != "" {
		slugVal = b.Slug
	}
	res, err := DB.Exec(`INSERT INTO blogs (slug,title,title_en,description,desc_en,content,content_en,image,category,category_en,read_time,show_home) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		slugVal, b.Title, b.TitleEN, b.Description, b.DescEN, b.Content, b.ContentEN, b.Image, b.Category, b.CategoryEN, b.ReadTime, b.ShowHome)
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal simpan blog"})
		return
	}
	id, _ := res.LastInsertId()
	b.ID = int(id)
	c.JSON(200, b)
}

func UpdateBlog(c *gin.Context) {
	var b Blog
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(400, gin.H{"error": "Data tidak valid"})
		return
	}
	if b.ShowHome {
		enforceHomeLimit(b.ID)
	}
	var slugVal interface{}
	if b.Slug != "" {
		slugVal = b.Slug
	}
	_, err := DB.Exec(`UPDATE blogs SET slug=?,title=?,title_en=?,description=?,desc_en=?,content=?,content_en=?,image=?,category=?,category_en=?,read_time=?,show_home=? WHERE id=?`,
		slugVal, b.Title, b.TitleEN, b.Description, b.DescEN, b.Content, b.ContentEN, b.Image, b.Category, b.CategoryEN, b.ReadTime, b.ShowHome, c.Param("id"))
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal update blog"})
		return
	}
	c.JSON(200, gin.H{"message": "Blog diperbarui"})
}

func DeleteBlog(c *gin.Context) {
	DB.Exec(`DELETE FROM blogs WHERE id=?`, c.Param("id"))
	c.JSON(200, gin.H{"message": "Blog dihapus"})
}

func SetHomeBlogs(c *gin.Context) {
	var body struct {
		IDs []int `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Data tidak valid"})
		return
	}
	if len(body.IDs) > 3 {
		c.JSON(400, gin.H{"error": "Maksimal 3 blog di homepage"})
		return
	}
	DB.Exec(`UPDATE blogs SET show_home=0`)
	for _, id := range body.IDs {
		DB.Exec(`UPDATE blogs SET show_home=1 WHERE id=?`, id)
	}
	c.JSON(200, gin.H{"message": "Homepage blog diperbarui"})
}

func enforceHomeLimit(excludeID int) {
	var count int
	DB.QueryRow(`SELECT COUNT(*) FROM blogs WHERE show_home=1 AND id!=?`, excludeID).Scan(&count)
	if count >= 3 {
		DB.Exec(`UPDATE blogs SET show_home=0 WHERE show_home=1 AND id!=? ORDER BY created_at ASC LIMIT 1`, excludeID)
	}
}

func GetUsers(c *gin.Context) {
	rows, _ := DB.Query(`SELECT id,username,email,role,created_at FROM users ORDER BY created_at DESC`)
	defer rows.Close()
	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, email, role, createdAt string
		rows.Scan(&id, &username, &email, &role, &createdAt)
		users = append(users, map[string]interface{}{
			"id": id, "username": username, "email": email, "role": role, "created_at": createdAt,
		})
	}
	if users == nil {
		users = []map[string]interface{}{}
	}
	c.JSON(200, users)
}

func UpdateUserRole(c *gin.Context) {
	claims := c.MustGet("claims").(*Claims)
	var body struct {
		Role string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Data tidak valid"})
		return
	}
	// Master admin hanya boleh set role user/admin (tidak boleh buat master_admin baru)
	if body.Role == "master_admin" {
		c.JSON(403, gin.H{"error": "Tidak bisa mengubah role menjadi master admin"})
		return
	}
	validRoles := map[string]bool{"user": true, "admin": true}
	if !validRoles[body.Role] {
		c.JSON(400, gin.H{"error": "Role tidak valid"})
		return
	}
	// Tidak boleh ubah role diri sendiri
	targetID := c.Param("id")
	if fmt.Sprintf("%d", claims.UserID) == targetID {
		c.JSON(403, gin.H{"error": "Tidak bisa mengubah role diri sendiri"})
		return
	}
	// Tidak boleh ubah role master_admin lain
	var targetRole string
	DB.QueryRow(`SELECT role FROM users WHERE id=?`, targetID).Scan(&targetRole)
	if targetRole == "master_admin" {
		c.JSON(403, gin.H{"error": "Tidak bisa mengubah role master admin"})
		return
	}
	DB.Exec(`UPDATE users SET role=? WHERE id=?`, body.Role, targetID)
	c.JSON(200, gin.H{"message": "Role diperbarui"})
}

func CreateUserByMaster(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Email == "" || body.Password == "" {
		c.JSON(400, gin.H{"error": "Data tidak lengkap"})
		return
	}
	// Hanya boleh buat akun user/admin
	if body.Role != "user" && body.Role != "admin" {
		c.JSON(400, gin.H{"error": "Role hanya boleh user atau admin"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	_, err := DB.Exec(`INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)`,
		body.Username, body.Email, string(hash), body.Role)
	if err != nil {
		c.JSON(400, gin.H{"error": "Username atau email sudah terdaftar"})
		return
	}
	c.JSON(200, gin.H{"message": "Akun berhasil dibuat"})
}

func UpdateUserPassword(c *gin.Context) {
	claims := c.MustGet("claims").(*Claims)
	targetID := c.Param("id")
	// Tidak boleh ubah password diri sendiri via endpoint ini
	if fmt.Sprintf("%d", claims.UserID) == targetID {
		c.JSON(403, gin.H{"error": "Gunakan fitur ganti password biasa"})
		return
	}
	// Tidak boleh ubah password master_admin lain
	var targetRole string
	DB.QueryRow(`SELECT role FROM users WHERE id=?`, targetID).Scan(&targetRole)
	if targetRole == "master_admin" {
		c.JSON(403, gin.H{"error": "Tidak bisa mengubah password master admin lain"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Password == "" {
		c.JSON(400, gin.H{"error": "Password baru wajib diisi"})
		return
	}
	if len(body.Password) < 6 {
		c.JSON(400, gin.H{"error": "Password minimal 6 karakter"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	DB.Exec(`UPDATE users SET password=? WHERE id=?`, string(hash), targetID)
	c.JSON(200, gin.H{"message": "Password berhasil diubah"})
}

func DeleteUser(c *gin.Context) {
	claims := c.MustGet("claims").(*Claims)
	targetID := c.Param("id")
	// Tidak boleh hapus diri sendiri
	if fmt.Sprintf("%d", claims.UserID) == targetID {
		c.JSON(403, gin.H{"error": "Tidak bisa menghapus akun sendiri"})
		return
	}
	// Tidak boleh hapus master_admin
	var targetRole string
	DB.QueryRow(`SELECT role FROM users WHERE id=?`, targetID).Scan(&targetRole)
	if targetRole == "master_admin" {
		c.JSON(403, gin.H{"error": "Tidak bisa menghapus master admin"})
		return
	}
	res, err := DB.Exec(`DELETE FROM users WHERE id=?`, targetID)
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal menghapus akun"})
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		c.JSON(404, gin.H{"error": "Akun tidak ditemukan"})
		return
	}
	c.JSON(200, gin.H{"message": "Akun berhasil dihapus"})
}

func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}

func GenerateArticle(c *gin.Context) {
	var body struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Language    string `json:"language"` // "id" atau "en"
		Style       string `json:"style"`    // "formal", "santai", "teknis"
		Length      string `json:"length"`   // "pendek", "sedang", "panjang"
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(400, gin.H{"error": "Judul wajib diisi"})
		return
	}

	apiKey := getEnv("ANTHROPIC_API_KEY", "")
	if apiKey == "" {
		c.JSON(500, gin.H{"error": "Anthropic API key belum dikonfigurasi"})
		return
	}

	// Default values
	if body.Language == "" { body.Language = "id" }
	if body.Style == ""    { body.Style = "santai" }
	if body.Length == ""   { body.Length = "sedang" }

	// Tentukan jumlah paragraf berdasarkan panjang
	paragrafCount := "3"
	if body.Length == "pendek" { paragrafCount = "2" }
	if body.Length == "panjang" { paragrafCount = "5" }

	lang := "Bahasa Indonesia"
	if body.Language == "en" { lang = "English" }

	prompt := fmt.Sprintf(`Tulis artikel blog dalam %s dengan ketentuan:
- Judul: %s
- Deskripsi/topik: %s
- Gaya bahasa: %s
- Panjang: %s (%s paragraf per bagian)

Struktur artikel:
1. Satu heading utama
2. 2-3 subheading
3. Setiap subheading diikuti %s paragraf
4. Satu quote yang relevan di tengah artikel
5. Satu list berisi 3-5 poin kesimpulan di akhir

PENTING: Balas HANYA dengan JSON array tanpa teks tambahan, tanpa markdown, tanpa backtick. Format:
[
  {"type":"heading","text":"..."},
  {"type":"paragraph","text":"..."},
  {"type":"subheading","text":"..."},
  {"type":"paragraph","text":"..."},
  {"type":"quote","text":"...","author":"..."},
  {"type":"subheading","text":"..."},
  {"type":"paragraph","text":"..."},
  {"type":"list","items":["...","...","..."]}
]`, lang, body.Title, body.Description, body.Style, body.Length, paragrafCount, paragrafCount)

	// Buat request ke Anthropic API
	reqBody := map[string]interface{}{
		"model":      "claude-haiku-4-5-20251001",
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	reqBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(reqBytes))
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal membuat request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": "Gagal menghubungi Anthropic API"})
		return
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)

	var anthropicResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &anthropicResp); err != nil {
		c.JSON(500, gin.H{"error": "Gagal parse response AI"})
		return
	}
	if anthropicResp.Error.Message != "" {
		c.JSON(500, gin.H{"error": anthropicResp.Error.Message})
		return
	}
	if len(anthropicResp.Content) == 0 {
		c.JSON(500, gin.H{"error": "AI tidak menghasilkan konten"})
		return
	}

	// Ambil teks JSON dari response
	rawText := strings.TrimSpace(anthropicResp.Content[0].Text)

	// Validasi bahwa response adalah JSON array yang valid
	var blocks []interface{}
	if err := json.Unmarshal([]byte(rawText), &blocks); err != nil {
		c.JSON(500, gin.H{"error": "AI tidak menghasilkan format yang valid, coba lagi"})
		return
	}

	c.JSON(200, gin.H{"blocks": blocks})
}

func main() {
	godotenv.Load()
	JWTSecret = []byte(getEnvOrFatal("JWT_SECRET"))
	initDB()
	 // baca .env
	r := gin.Default()
	// CORS: baca dari env, fallback ke localhost untuk development
	allowedOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000")
	origins := strings.Split(allowedOrigins, ",")
	r.Use(cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	api := r.Group("/api")

	// ── Public
	api.POST("/register", Register)
	api.POST("/login", Login)
	api.POST("/forgot-password", ForgotPassword)
	api.POST("/reset-password", ResetPassword)
	api.GET("/blogs", GetBlogs)
	api.GET("/blogs/home", GetHomeBlogs)
	api.GET("/blogs/:id", GetBlogByID) // support slug string maupun id angka

	// ── Auth required
	auth := api.Group("/")
	auth.Use(AuthMiddleware())
	auth.GET("/me", GetMe)

	// ── Admin + Master Admin
	adminOnly := api.Group("/admin")
	adminOnly.Use(AuthMiddleware(), RoleMiddleware("admin", "master_admin"))
	adminOnly.POST("/blogs", CreateBlog)
	adminOnly.PUT("/blogs/:id", UpdateBlog)
	adminOnly.DELETE("/blogs/:id", DeleteBlog)
	adminOnly.PATCH("/blogs/home", SetHomeBlogs)
	adminOnly.POST("/generate", GenerateArticle)

	// ── Master Admin only
	masterOnly := api.Group("/master")
	masterOnly.Use(AuthMiddleware(), RoleMiddleware("master_admin"))
	masterOnly.GET("/users", GetUsers)
	masterOnly.POST("/users", CreateUserByMaster)
	masterOnly.PATCH("/users/:id/role", UpdateUserRole)
	masterOnly.PATCH("/users/:id/password", UpdateUserPassword)
	masterOnly.DELETE("/users/:id", DeleteUser)

	port := getEnv("PORT", "8080")
	log.Printf("🚀 Server jalan di port %s", port)
	r.Run(":" + port)
}
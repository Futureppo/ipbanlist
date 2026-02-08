package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultDBPath    = "data/ipban.db"
	defaultListen    = ":8080"
	configAPIKey     = "api_key"
	adminCookieName  = "ipban_admin_session"
	adminSessionTTL  = 24 * time.Hour
	defaultPageSize  = 20
	maxPageSize      = 200
	minCustomKeySize = 16
)

type Blacklist struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	IP        string    `json:"ip" gorm:"size:45;uniqueIndex;not null"`
	Reason    string    `json:"reason" gorm:"size:255"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Config struct {
	Key       string    `json:"key" gorm:"primaryKey;size:64"`
	Value     string    `json:"value" gorm:"size:512;not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type App struct {
	db            *gorm.DB
	adminPassword string
	sessionSecret []byte
	apiKeyCache   atomic.Value // string
}

func main() {
	dbPath := getEnv("DB_PATH", defaultDBPath)
	if err := ensureDir(filepath.Dir(dbPath)); err != nil {
		log.Fatalf("failed to create db dir: %v", err)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		PrepareStmt:    true,
		TranslateError: true,
	})
	if err != nil {
		log.Fatalf("failed to open sqlite database: %v", err)
	}

	if err := db.AutoMigrate(&Blacklist{}, &Config{}); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	sqlDB, err := db.DB()
	if err == nil {
		// SQLite runs best with a single write connection in low-resource environments.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0)
	}

	secret, err := randomBytes(32)
	if err != nil {
		log.Fatalf("failed to initialize session secret: %v", err)
	}

	app := &App{
		db:            db,
		adminPassword: getEnv("ADMIN_PASS", "admin"),
		sessionSecret: secret,
	}

	if err := app.ensureAPIKey(); err != nil {
		log.Fatalf("failed to initialize api key: %v", err)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
	router.Static("/static", "./static")
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	apiV1 := router.Group("/api/v1")
	apiV1.Use(app.apiKeyAuthMiddleware())
	{
		apiV1.GET("/ips", app.handleGetIPs)
		apiV1.GET("/details", app.handleGetDetails)
	}

	admin := router.Group("/admin")
	{
		admin.POST("/login", app.handleAdminLogin)

		protected := admin.Group("")
		protected.Use(app.adminAuthMiddleware())
		{
			protected.POST("/logout", app.handleAdminLogout)
			protected.GET("/stats", app.handleAdminStats)
			protected.GET("/list", app.handleAdminList)
			protected.POST("/add", app.handleAdminAdd)
			protected.PUT("/update", app.handleAdminUpdate)
			protected.DELETE("/delete", app.handleAdminDelete)
			protected.GET("/config/key", app.handleAdminGetKey)
			protected.PUT("/config/key", app.handleAdminSetKey)
		}
	}

	router.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/admin/") {
			jsonError(c, http.StatusNotFound, "route not found")
			return
		}
		c.File("./static/index.html")
	})

	listenAddr := getListenAddr()
	log.Printf("ip blacklist service listening on %s", listenAddr)
	if err := router.Run(listenAddr); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func (a *App) apiKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientKey := strings.TrimSpace(c.GetHeader("X-API-KEY"))
		if clientKey == "" {
			jsonError(c, http.StatusUnauthorized, "missing X-API-KEY header")
			c.Abort()
			return
		}

		serverKey, err := a.currentAPIKey()
		if err != nil {
			jsonError(c, http.StatusInternalServerError, "failed to validate api key")
			c.Abort()
			return
		}

		if subtle.ConstantTimeCompare([]byte(clientKey), []byte(serverKey)) != 1 {
			jsonError(c, http.StatusUnauthorized, "invalid api key")
			c.Abort()
			return
		}

		c.Next()
	}
}

func (a *App) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(adminCookieName)
		if err != nil || !a.validateSessionToken(token) {
			jsonError(c, http.StatusUnauthorized, "unauthorized")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (a *App) handleGetIPs(c *gin.Context) {
	var ips []string

	// Optimization: only fetch the IP column (no full rows) to reduce SQLite I/O and response size.
	// Generated SQL is equivalent to: SELECT ip FROM blacklists ORDER BY id DESC;
	if err := a.db.Model(&Blacklist{}).Order("id DESC").Pluck("ip", &ips).Error; err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to fetch ips")
		return
	}

	c.JSON(http.StatusOK, ips)
}

func (a *App) handleGetDetails(c *gin.Context) {
	type ipDetail struct {
		IP        string    `json:"ip"`
		Reason    string    `json:"reason"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
	}

	var details []ipDetail
	if err := a.db.Model(&Blacklist{}).
		Select("ip, reason, created_at, updated_at").
		Order("id DESC").
		Find(&details).Error; err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to fetch ip details")
		return
	}

	c.JSON(http.StatusOK, details)
}

func (a *App) handleAdminLogin(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(a.adminPassword)) != 1 {
		jsonError(c, http.StatusUnauthorized, "invalid password")
		return
	}

	token, err := a.createSessionToken()
	if err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to create session")
		return
	}

	secureCookie := isHTTPSRequest(c.Request)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(adminCookieName, token, int(adminSessionTTL.Seconds()), "/", "", secureCookie, true)

	c.JSON(http.StatusOK, gin.H{"message": "login successful"})
}

func (a *App) handleAdminLogout(c *gin.Context) {
	secureCookie := isHTTPSRequest(c.Request)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(adminCookieName, "", -1, "/", "", secureCookie, true)
	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}

func (a *App) handleAdminStats(c *gin.Context) {
	var total int64
	if err := a.db.Model(&Blacklist{}).Count(&total).Error; err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to fetch stats")
		return
	}

	c.JSON(http.StatusOK, gin.H{"count": total})
}

func (a *App) handleAdminList(c *gin.Context) {
	page := parsePositiveInt(c.DefaultQuery("page", "1"), 1)
	pageSize := parsePositiveInt(c.DefaultQuery("page_size", strconv.Itoa(defaultPageSize)), defaultPageSize)
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	var total int64
	if err := a.db.Model(&Blacklist{}).Count(&total).Error; err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to count blacklist")
		return
	}

	var rows []Blacklist
	offset := (page - 1) * pageSize
	if err := a.db.Order("id DESC").Limit(pageSize).Offset(offset).Find(&rows).Error; err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to fetch blacklist")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"items":     rows,
	})
}

func (a *App) handleAdminAdd(c *gin.Context) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	normalizedIP, err := normalizeIP(req.IP)
	if err != nil {
		jsonError(c, http.StatusBadRequest, err.Error())
		return
	}

	entry := Blacklist{
		IP:     normalizedIP,
		Reason: strings.TrimSpace(req.Reason),
	}

	if err := a.db.Create(&entry).Error; err != nil {
		if isDuplicateError(err) {
			jsonError(c, http.StatusConflict, "ip already exists")
			return
		}
		jsonError(c, http.StatusInternalServerError, "failed to add ip")
		return
	}

	c.JSON(http.StatusCreated, entry)
}

func (a *App) handleAdminUpdate(c *gin.Context) {
	var req struct {
		ID     uint   `json:"id"`
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		jsonError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		jsonError(c, http.StatusBadRequest, "reason is required")
		return
	}

	query := a.db.Model(&Blacklist{})
	lookupByIP := ""

	switch {
	case req.ID > 0:
		query = query.Where("id = ?", req.ID)
	case strings.TrimSpace(req.IP) != "":
		normalizedIP, err := normalizeIP(req.IP)
		if err != nil {
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		lookupByIP = normalizedIP
		query = query.Where("ip = ?", normalizedIP)
	default:
		jsonError(c, http.StatusBadRequest, "either id or ip is required")
		return
	}

	res := query.Updates(map[string]any{
		"reason":     reason,
		"updated_at": time.Now().UTC(),
	})
	if res.Error != nil {
		jsonError(c, http.StatusInternalServerError, "failed to update ip")
		return
	}
	if res.RowsAffected == 0 {
		jsonError(c, http.StatusNotFound, "ip not found")
		return
	}

	var updated Blacklist
	if req.ID > 0 {
		if err := a.db.First(&updated, req.ID).Error; err != nil {
			jsonError(c, http.StatusInternalServerError, "failed to fetch updated row")
			return
		}
	} else {
		if err := a.db.First(&updated, "ip = ?", lookupByIP).Error; err != nil {
			jsonError(c, http.StatusInternalServerError, "failed to fetch updated row")
			return
		}
	}

	c.JSON(http.StatusOK, updated)
}

func (a *App) handleAdminDelete(c *gin.Context) {
	var req struct {
		ID uint   `json:"id"`
		IP string `json:"ip"`
	}

	_ = c.ShouldBindJSON(&req)

	if req.ID == 0 && strings.TrimSpace(req.IP) == "" {
		if idParam := strings.TrimSpace(c.Query("id")); idParam != "" {
			req.ID = uint(parsePositiveInt(idParam, 0))
		}
		req.IP = strings.TrimSpace(c.Query("ip"))
	}

	tx := a.db
	switch {
	case req.ID > 0:
		tx = tx.Where("id = ?", req.ID)
	case strings.TrimSpace(req.IP) != "":
		normalizedIP, err := normalizeIP(req.IP)
		if err != nil {
			jsonError(c, http.StatusBadRequest, err.Error())
			return
		}
		tx = tx.Where("ip = ?", normalizedIP)
	default:
		jsonError(c, http.StatusBadRequest, "either id or ip is required")
		return
	}

	res := tx.Delete(&Blacklist{})
	if res.Error != nil {
		jsonError(c, http.StatusInternalServerError, "failed to delete ip")
		return
	}
	if res.RowsAffected == 0 {
		jsonError(c, http.StatusNotFound, "ip not found")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (a *App) handleAdminGetKey(c *gin.Context) {
	key, err := a.currentAPIKey()
	if err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to read api key")
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_key": key})
}

func (a *App) handleAdminSetKey(c *gin.Context) {
	var req struct {
		APIKey string `json:"api_key"`
	}

	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		jsonError(c, http.StatusBadRequest, "invalid request body")
		return
	}

	key := strings.TrimSpace(req.APIKey)
	if key == "" {
		var err error
		key, err = generateSecureToken(32)
		if err != nil {
			jsonError(c, http.StatusInternalServerError, "failed to generate api key")
			return
		}
	}

	if len(key) < minCustomKeySize {
		jsonError(c, http.StatusBadRequest, fmt.Sprintf("api key must be at least %d characters", minCustomKeySize))
		return
	}

	if err := a.setAPIKey(key); err != nil {
		jsonError(c, http.StatusInternalServerError, "failed to update api key")
		return
	}

	c.JSON(http.StatusOK, gin.H{"api_key": key})
}

func (a *App) ensureAPIKey() error {
	key, err := a.getConfigValue(configAPIKey)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		key, err = generateSecureToken(32)
		if err != nil {
			return err
		}
		if err := a.setConfigValue(configAPIKey, key); err != nil {
			return err
		}
	}

	key = strings.TrimSpace(key)
	if key == "" {
		newKey, err := generateSecureToken(32)
		if err != nil {
			return err
		}
		if err := a.setConfigValue(configAPIKey, newKey); err != nil {
			return err
		}
		key = newKey
	}

	a.apiKeyCache.Store(key)
	return nil
}

func (a *App) currentAPIKey() (string, error) {
	if v := a.apiKeyCache.Load(); v != nil {
		if key, ok := v.(string); ok && key != "" {
			return key, nil
		}
	}

	key, err := a.getConfigValue(configAPIKey)
	if err != nil {
		return "", err
	}
	a.apiKeyCache.Store(key)
	return key, nil
}

func (a *App) setAPIKey(key string) error {
	if err := a.setConfigValue(configAPIKey, key); err != nil {
		return err
	}
	a.apiKeyCache.Store(key)
	return nil
}

func (a *App) getConfigValue(cfgKey string) (string, error) {
	var cfg Config
	if err := a.db.First(&cfg, "key = ?", cfgKey).Error; err != nil {
		return "", err
	}
	return cfg.Value, nil
}

func (a *App) setConfigValue(cfgKey, cfgValue string) error {
	cfg := Config{
		Key:   cfgKey,
		Value: cfgValue,
	}
	return a.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&cfg).Error
}

func (a *App) createSessionToken() (string, error) {
	nonce, err := generateSecureToken(24)
	if err != nil {
		return "", err
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	payload := timestamp + "." + nonce
	signature := signHMAC(payload, a.sessionSecret)

	return payload + "." + signature, nil
}

func (a *App) validateSessionToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	payload := parts[0] + "." + parts[1]
	expectedSig := signHMAC(payload, a.sessionSecret)
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(expectedSig)) != 1 {
		return false
	}

	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}

	issuedAt := time.Unix(ts, 0)
	if issuedAt.After(time.Now().Add(5 * time.Minute)) {
		return false
	}

	return time.Since(issuedAt) <= adminSessionTTL
}

func signHMAC(payload string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func normalizeIP(input string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(input))
	if ip == nil {
		return "", errors.New("invalid ip address")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}
	return ip.String(), nil
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func generateSecureToken(bytesLen int) (string, error) {
	buf, err := randomBytes(bytesLen)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parsePositiveInt(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func getListenAddr() string {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		return defaultListen
	}
	if strings.Contains(port, ":") {
		return port
	}
	return ":" + port
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func ensureDir(path string) error {
	if path == "." || path == "" {
		return nil
	}
	return os.MkdirAll(path, 0o755)
}

func isDuplicateError(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicated key")
}

func isHTTPSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func jsonError(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"error": message})
}

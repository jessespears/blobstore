package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

func setupTestRedis(t *testing.T) *miniredis.Miniredis {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	rdb = redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	return mr
}

func setupTestMinio(t *testing.T) {
	var err error
	endpoint := "localhost:9000"
	if testing.Short() {
		t.Skip("skipping MinIO tests in short mode")
	}
	mc, err = minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	if err != nil {
		t.Skipf("MinIO not available: %v", err)
	}
	ctx := context.Background()
	exists, err := mc.BucketExists(ctx, minioBucket)
	if err != nil {
		t.Skipf("MinIO not available: %v", err)
	}
	if !exists {
		mc.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{})
	}
}

func createTestUser(t *testing.T, mr *miniredis.Miniredis, username, password string) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	mr.HSet("users:"+username, "password", string(hashed))
}

func getSessionCookie(t *testing.T, username, password string) *http.Cookie {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)
	resp := w.Result()
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	t.Fatal("no session cookie returned")
	return nil
}

func TestHandleRegister(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{"valid registration", "newuser", "password123", http.StatusCreated},
		{"empty username", "", "password123", http.StatusBadRequest},
		{"empty password", "newuser2", "", http.StatusBadRequest},
		{"username too long", strings.Repeat("a", 256), "password", http.StatusBadRequest},
		{"password too long", "user", strings.Repeat("a", 256), http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("username", tt.username)
			form.Set("password", tt.password)
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handleRegister(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandleRegisterDuplicate(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "existinguser", "password")

	form := url.Values{}
	form.Set("username", "existinguser")
	form.Set("password", "newpassword")
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleRegister(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("got status %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestHandleRegisterMethodNotAllowed(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	w := httptest.NewRecorder()
	handleRegister(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleLogin(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "correctpassword")

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
		wantCookie bool
	}{
		{"valid login", "testuser", "correctpassword", http.StatusOK, true},
		{"wrong password", "testuser", "wrongpassword", http.StatusUnauthorized, false},
		{"nonexistent user", "nouser", "password", http.StatusUnauthorized, false},
		{"empty username", "", "password", http.StatusBadRequest, false},
		{"empty password", "testuser", "", http.StatusBadRequest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("username", tt.username)
			form.Set("password", tt.password)
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handleLogin(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", w.Code, tt.wantStatus)
			}

			resp := w.Result()
			hasCookie := false
			for _, c := range resp.Cookies() {
				if c.Name == "session" {
					hasCookie = true
					break
				}
			}
			if hasCookie != tt.wantCookie {
				t.Errorf("cookie presence: got %v, want %v", hasCookie, tt.wantCookie)
			}
		})
	}
}

func TestHandleLoginMethodNotAllowed(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleLoginLengthValidation(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	form := url.Values{}
	form.Set("username", strings.Repeat("a", 256))
	form.Set("password", "password")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetSession(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	mr.Set("sessions:validtoken", "testuser")
	mr.SetTTL("sessions:validtoken", time.Hour)

	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantUser  string
		wantError bool
	}{
		{
			"valid session",
			&http.Cookie{Name: "session", Value: "validtoken"},
			"testuser",
			false,
		},
		{
			"invalid session",
			&http.Cookie{Name: "session", Value: "invalidtoken"},
			"",
			true,
		},
		{
			"no cookie",
			nil,
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			user, err := getSession(req)
			if tt.wantError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if user != tt.wantUser {
				t.Errorf("got user %q, want %q", user, tt.wantUser)
			}
		})
	}
}

func TestHandleGetUnauthorized(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/get?key=test", nil)
	w := httptest.NewRecorder()
	handleGet(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleGetMissingKey(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	req := httptest.NewRequest(http.MethodGet, "/get", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleGet(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleGetNotFound(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	req := httptest.NewRequest(http.MethodGet, "/get?key=nonexistent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleGet(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleGetSmallValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	mr.Set("blobs:testuser:mykey", "smallvalue")

	req := httptest.NewRequest(http.MethodGet, "/get?key=mykey", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleGet(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "smallvalue" {
		t.Errorf("got body %q, want %q", w.Body.String(), "smallvalue")
	}
}

func TestHandlePutUnauthorized(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	form := url.Values{}
	form.Set("value", "testvalue")
	req := httptest.NewRequest(http.MethodPost, "/put?key=test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handlePut(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandlePutMethodNotAllowed(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/put?key=test", nil)
	w := httptest.NewRecorder()
	handlePut(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlePutMissingParams(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"missing key", "", "value"},
		{"missing value", "key", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("value", tt.value)
			url := "/put"
			if tt.key != "" {
				url += "?key=" + tt.key
			}
			req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			w := httptest.NewRecorder()
			handlePut(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHandlePutSmallValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	form := url.Values{}
	form.Set("value", "smallvalue")
	req := httptest.NewRequest(http.MethodPost, "/put?key=mykey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handlePut(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	stored, err := mr.Get("blobs:testuser:mykey")
	if err != nil {
		t.Fatalf("key not found in redis: %v", err)
	}
	if stored != "smallvalue" {
		t.Errorf("got stored value %q, want %q", stored, "smallvalue")
	}
}

func TestHandlePutLargeValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()
	setupTestMinio(t)

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	largeValue := strings.Repeat("x", 600)
	form := url.Values{}
	form.Set("value", largeValue)
	req := httptest.NewRequest(http.MethodPost, "/put?key=largekey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handlePut(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	stored, err := mr.Get("blobs:testuser:largekey")
	if err != nil {
		t.Fatalf("key not found in redis: %v", err)
	}
	if !strings.HasPrefix(stored, "minio:") {
		t.Errorf("expected minio: prefix, got %q", stored)
	}
}

func TestHandleDeleteUnauthorized(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodDelete, "/delete?key=test", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleDeleteMethodNotAllowed(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	req := httptest.NewRequest(http.MethodGet, "/delete?key=test", nil)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleDeleteMissingKey(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	req := httptest.NewRequest(http.MethodDelete, "/delete", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleDeleteNotFound(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	req := httptest.NewRequest(http.MethodDelete, "/delete?key=nonexistent", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleDeleteSmallValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	mr.Set("blobs:testuser:mykey", "smallvalue")

	req := httptest.NewRequest(http.MethodDelete, "/delete?key=mykey", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", w.Code, http.StatusOK)
	}

	if mr.Exists("blobs:testuser:mykey") {
		t.Error("key should have been deleted")
	}
}

func TestHandleDeleteLargeValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()
	setupTestMinio(t)

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	objectKey := "testuser/deletekey"
	_, err := mc.PutObject(ctx, minioBucket, objectKey, bytes.NewReader([]byte("largedata")), 9, minio.PutObjectOptions{})
	if err != nil {
		t.Fatalf("failed to create test object: %v", err)
	}
	mr.Set("blobs:testuser:deletekey", "minio:"+objectKey)

	req := httptest.NewRequest(http.MethodDelete, "/delete?key=deletekey", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	handleDelete(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got status %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}

	if mr.Exists("blobs:testuser:deletekey") {
		t.Error("redis key should have been deleted")
	}
}

func TestHandleFortune(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/fortune", nil)
	w := httptest.NewRecorder()
	handleFortune(w, req)

	// Fortune may or may not be installed, so we just check it doesn't panic
	// and returns either OK or Internal Server Error
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, want %d or %d", w.Code, http.StatusOK, http.StatusInternalServerError)
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	// Put a value
	form := url.Values{}
	form.Set("value", "roundtripvalue")
	putReq := httptest.NewRequest(http.MethodPost, "/put?key=rtkey", strings.NewReader(form.Encode()))
	putReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	putReq.AddCookie(cookie)
	putW := httptest.NewRecorder()
	handlePut(putW, putReq)

	if putW.Code != http.StatusOK {
		t.Fatalf("put failed with status %d", putW.Code)
	}

	// Get the value back
	getReq := httptest.NewRequest(http.MethodGet, "/get?key=rtkey", nil)
	getReq.AddCookie(cookie)
	getW := httptest.NewRecorder()
	handleGet(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("get failed with status %d", getW.Code)
	}
	if getW.Body.String() != "roundtripvalue" {
		t.Errorf("got %q, want %q", getW.Body.String(), "roundtripvalue")
	}
}

func TestPutGetRoundTripLargeValue(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()
	setupTestMinio(t)

	createTestUser(t, mr, "testuser", "password")
	cookie := getSessionCookie(t, "testuser", "password")

	largeValue := strings.Repeat("y", 1000)

	// Put a large value
	form := url.Values{}
	form.Set("value", largeValue)
	putReq := httptest.NewRequest(http.MethodPost, "/put?key=largertkey", strings.NewReader(form.Encode()))
	putReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	putReq.AddCookie(cookie)
	putW := httptest.NewRecorder()
	handlePut(putW, putReq)

	if putW.Code != http.StatusOK {
		t.Fatalf("put failed with status %d: %s", putW.Code, putW.Body.String())
	}

	// Verify it's stored in MinIO
	stored, _ := mr.Get("blobs:testuser:largertkey")
	if !strings.HasPrefix(stored, "minio:") {
		t.Fatalf("expected minio: prefix, got %q", stored)
	}

	// Get the value back
	getReq := httptest.NewRequest(http.MethodGet, "/get?key=largertkey", nil)
	getReq.AddCookie(cookie)
	getW := httptest.NewRecorder()
	handleGet(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("get failed with status %d: %s", getW.Code, getW.Body.String())
	}
	if getW.Body.String() != largeValue {
		t.Errorf("got length %d, want length %d", len(getW.Body.String()), len(largeValue))
	}
}

func TestUserIsolation(t *testing.T) {
	mr := setupTestRedis(t)
	defer mr.Close()

	createTestUser(t, mr, "user1", "password1")
	createTestUser(t, mr, "user2", "password2")
	cookie1 := getSessionCookie(t, "user1", "password1")
	cookie2 := getSessionCookie(t, "user2", "password2")

	// User1 puts a value
	form := url.Values{}
	form.Set("value", "user1secret")
	putReq := httptest.NewRequest(http.MethodPost, "/put?key=secret", strings.NewReader(form.Encode()))
	putReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	putReq.AddCookie(cookie1)
	putW := httptest.NewRecorder()
	handlePut(putW, putReq)

	// User2 tries to get user1's value (should not find it)
	getReq := httptest.NewRequest(http.MethodGet, "/get?key=secret", nil)
	getReq.AddCookie(cookie2)
	getW := httptest.NewRecorder()
	handleGet(getW, getReq)

	if getW.Code != http.StatusNotFound {
		t.Errorf("user2 should not see user1's key, got status %d", getW.Code)
	}

	// User1 can get their own value
	getReq2 := httptest.NewRequest(http.MethodGet, "/get?key=secret", nil)
	getReq2.AddCookie(cookie1)
	getW2 := httptest.NewRecorder()
	handleGet(getW2, getReq2)

	if getW2.Code != http.StatusOK {
		t.Errorf("user1 should see their own key, got status %d", getW2.Code)
	}
	if getW2.Body.String() != "user1secret" {
		t.Errorf("got %q, want %q", getW2.Body.String(), "user1secret")
	}
}

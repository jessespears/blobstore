package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var redisLatency = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "redis_operation_duration_seconds",
		Help:    "Duration of Redis operations",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"operation"},
)

var minioLatency = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "minio_operation_duration_seconds",
		Help:    "Duration of MinIO operations",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"operation"},
)

func init() {
	prometheus.MustRegister(redisLatency)
	prometheus.MustRegister(minioLatency)
}

var rdb *redis.Client
var mc *minio.Client
var ctx = context.Background()

const sessionExpiry = 24 * time.Hour
const minioBucket = "blobs"
const minioThreshold = 512

func getSession(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return "", err
	}
	start := time.Now()
	result, err := rdb.Get(ctx, "sessions:"+cookie.Value).Result()
	redisLatency.WithLabelValues("get").Observe(time.Since(start).Seconds())
	return result, err
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	if len(username) > 255 || len(password) > 255 {
		http.Error(w, "username and password must be 255 bytes or less", http.StatusBadRequest)
		return
	}

	start := time.Now()
	stored, err := rdb.HGet(ctx, "users:"+username, "password").Result()
	redisLatency.WithLabelValues("hget").Observe(time.Since(start).Seconds())
	if err == redis.Nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sessionID := hex.EncodeToString(token)

	start = time.Now()
	if err := rdb.Set(ctx, "sessions:"+sessionID, username, sessionExpiry).Err(); err != nil {
		redisLatency.WithLabelValues("set").Observe(time.Since(start).Seconds())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redisLatency.WithLabelValues("set").Observe(time.Since(start).Seconds())

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(sessionExpiry.Seconds()),
	})

	w.Write([]byte("ok"))
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}

	if len(username) > 255 || len(password) > 255 {
		http.Error(w, "username and password must be 255 bytes or less", http.StatusBadRequest)
		return
	}

	start := time.Now()
	exists, err := rdb.Exists(ctx, "users:"+username).Result()
	redisLatency.WithLabelValues("exists").Observe(time.Since(start).Seconds())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	start = time.Now()
	if err := rdb.HSet(ctx, "users:"+username, "password", string(hashed)).Err(); err != nil {
		redisLatency.WithLabelValues("hset").Observe(time.Since(start).Seconds())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redisLatency.WithLabelValues("hset").Observe(time.Since(start).Seconds())

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("ok"))
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	username, err := getSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}

	start := time.Now()
	value, err := rdb.Get(ctx, "blobs:"+username+":"+key).Result()
	redisLatency.WithLabelValues("get").Observe(time.Since(start).Seconds())
	if err == redis.Nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.HasPrefix(value, "minio:") {
		objectKey := strings.TrimPrefix(value, "minio:")
		start = time.Now()
		obj, err := mc.GetObject(ctx, minioBucket, objectKey, minio.GetObjectOptions{})
		if err != nil {
			minioLatency.WithLabelValues("get").Observe(time.Since(start).Seconds())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer obj.Close()
		data, err := io.ReadAll(obj)
		minioLatency.WithLabelValues("get").Observe(time.Since(start).Seconds())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
		return
	}

	w.Write([]byte(value))
}

func handlePut(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, err := getSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Query().Get("key")
	value := r.FormValue("value")
	if key == "" || value == "" {
		http.Error(w, "key and value required", http.StatusBadRequest)
		return
	}

	redisKey := "blobs:" + username + ":" + key
	var redisValue string

	if len(value) > minioThreshold {
		objectKey := username + "/" + key
		start := time.Now()
		_, err := mc.PutObject(ctx, minioBucket, objectKey, bytes.NewReader([]byte(value)), int64(len(value)), minio.PutObjectOptions{})
		minioLatency.WithLabelValues("put").Observe(time.Since(start).Seconds())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		redisValue = "minio:" + objectKey
	} else {
		redisValue = value
	}

	start := time.Now()
	if err := rdb.Set(ctx, redisKey, redisValue, 0).Err(); err != nil {
		redisLatency.WithLabelValues("set").Observe(time.Since(start).Seconds())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redisLatency.WithLabelValues("set").Observe(time.Since(start).Seconds())

	w.Write([]byte("ok"))
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username, err := getSession(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "key required", http.StatusBadRequest)
		return
	}

	redisKey := "blobs:" + username + ":" + key

	start := time.Now()
	value, err := rdb.Get(ctx, redisKey).Result()
	redisLatency.WithLabelValues("get").Observe(time.Since(start).Seconds())
	if err == redis.Nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if strings.HasPrefix(value, "minio:") {
		objectKey := strings.TrimPrefix(value, "minio:")
		start = time.Now()
		err := mc.RemoveObject(ctx, minioBucket, objectKey, minio.RemoveObjectOptions{})
		minioLatency.WithLabelValues("remove").Observe(time.Since(start).Seconds())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	start = time.Now()
	if err := rdb.Del(ctx, redisKey).Err(); err != nil {
		redisLatency.WithLabelValues("del").Observe(time.Since(start).Seconds())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redisLatency.WithLabelValues("del").Observe(time.Since(start).Seconds())

	w.Write([]byte("ok"))
}

func handleFortune(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("fortune").Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func main() {
	rdb = redis.NewClient(&redis.Options{
		Addr: "redis:6379",
	})

	var err error
	mc, err = minio.New("minio:9000", &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	if err != nil {
		panic(err)
	}

	exists, err := mc.BucketExists(ctx, minioBucket)
	if err != nil {
		panic(err)
	}
	if !exists {
		if err := mc.MakeBucket(ctx, minioBucket, minio.MakeBucketOptions{}); err != nil {
			panic(err)
		}
	}

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/get", handleGet)
	http.HandleFunc("/put", handlePut)
	http.HandleFunc("/delete", handleDelete)
	http.HandleFunc("/fortune", handleFortune)
	http.Handle("/metrics", promhttp.Handler())

	http.ListenAndServe(":8080", nil)
}

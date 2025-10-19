// Copyright 2024 The NewBee Authors. All Rights Reserved.

package encryption

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/keys"
	"github.com/coder-lulu/newbee-common/utils/crypto"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestPlugin(t *testing.T) (*EncryptionPlugin, *crypto.AESGCMCipher, string) {
	keyBase64, err := crypto.GenerateKeyBase64(crypto.AES256KeySize)
	require.NoError(t, err)

	cipher, err := crypto.NewAESGCMCipherFromBase64(keyBase64)
	require.NoError(t, err)

	config := &framework.UnifiedConfig{
		Encryption: &framework.EncryptionConfig{
			Enabled:      true,
			Key:          keyBase64,
			SkipPaths:    []string{"/health"},
			ForceEncrypt: false,
		},
	}

	redisMock := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	core := &framework.CoreServices{
		Config:         config,
		Context:        context.Background(),
		Redis:          redisMock,
		ContextManager: keys.NewContextManager(),
	}

	plugin := NewEncryptionPlugin().(*EncryptionPlugin)
	err = plugin.Init(core)
	require.NoError(t, err)

	return plugin, cipher, keyBase64
}

func TestEncryptionPlugin_ResponseEncryption(t *testing.T) {
	plugin, cipher, _ := setupTestPlugin(t)

	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"code": 0,
			"msg":  "success",
			"data": map[string]interface{}{
				"username": "testuser",
				"email":    "test@example.com",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/user/info", nil)
	req.Header.Set(HeaderEncryptEnable, "true")
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get(HeaderEncryptIV))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, float64(0), response["code"])
	assert.Equal(t, "success", response["msg"])
	assert.NotNil(t, response["data"])

	encryptedData, ok := response["data"].(string)
	require.True(t, ok, "data should be string (encrypted)")

	ivHeader := w.Header().Get(HeaderEncryptIV)
	decryptedData, err := cipher.DecryptFromBase64(encryptedData, ivHeader)
	require.NoError(t, err)

	var originalData map[string]interface{}
	err = json.Unmarshal(decryptedData, &originalData)
	require.NoError(t, err)

	assert.Equal(t, "testuser", originalData["username"])
	assert.Equal(t, "test@example.com", originalData["email"])
}

func TestEncryptionPlugin_RequestDecryption(t *testing.T) {
	plugin, cipher, _ := setupTestPlugin(t)

	var receivedBody map[string]interface{}
	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "received",
		})
	})

	requestData := map[string]interface{}{
		"username": "admin",
		"password": "secret123",
	}
	plaintext, _ := json.Marshal(requestData)

	encryptedBody, iv, err := cipher.EncryptToBase64(plaintext)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(encryptedBody)))
	req.Header.Set(HeaderEncryptEnable, "true")
	req.Header.Set(HeaderEncryptIV, iv)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "admin", receivedBody["username"])
	assert.Equal(t, "secret123", receivedBody["password"])
}

func TestEncryptionPlugin_SkipPath(t *testing.T) {
	plugin, _, _ := setupTestPlugin(t)

	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "healthy",
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(HeaderEncryptEnable, "true")
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(HeaderEncryptIV))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
}

func TestEncryptionPlugin_DisabledByDefault(t *testing.T) {
	plugin, _, _ := setupTestPlugin(t)

	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"code": 0,
			"msg":  "success",
			"data": "plain text data",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get(HeaderEncryptIV))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "plain text data", response["data"])
}

func TestEncryptionPlugin_ResponseWithoutData(t *testing.T) {
	plugin, _, _ := setupTestPlugin(t)

	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"code": 0,
			"msg":  "no data response",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.Header.Set(HeaderEncryptEnable, "true")
	w := httptest.NewRecorder()

	handler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, float64(0), response["code"])
	assert.Equal(t, "no data response", response["msg"])
}

func TestEncryptionPlugin_InvalidIV(t *testing.T) {
	plugin, cipher, _ := setupTestPlugin(t)

	requestData := map[string]interface{}{
		"test": "data",
	}
	plaintext, _ := json.Marshal(requestData)
	encryptedBody, _, _ := cipher.EncryptToBase64(plaintext)

	handler := plugin.Handle(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/test", bytes.NewReader([]byte(encryptedBody)))
	req.Header.Set(HeaderEncryptEnable, "true")
	req.Header.Set(HeaderEncryptIV, "invalid-base64!!!")

	w := httptest.NewRecorder()
	handler(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

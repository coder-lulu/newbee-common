// Copyright 2024 The NewBee Authors. All Rights Reserved.

package encryption

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/coder-lulu/newbee-common/utils/crypto"
)

type encryptedResponseWriter struct {
	http.ResponseWriter
	cipher        *crypto.AESGCMCipher
	buffer        *bytes.Buffer
	statusCode    int
	headerWritten bool
}

func newEncryptedResponseWriter(w http.ResponseWriter, cipher *crypto.AESGCMCipher) *encryptedResponseWriter {
	return &encryptedResponseWriter{
		ResponseWriter: w,
		cipher:         cipher,
		buffer:         new(bytes.Buffer),
		statusCode:     http.StatusOK,
	}
}

func (w *encryptedResponseWriter) Write(b []byte) (int, error) {
	return w.buffer.Write(b)
}

func (w *encryptedResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.headerWritten = true
}

func (w *encryptedResponseWriter) Flush() error {
	if w.buffer.Len() == 0 {
		if w.headerWritten {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		return nil
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.buffer.Bytes(), &response); err != nil {
		if w.headerWritten {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		_, writeErr := w.ResponseWriter.Write(w.buffer.Bytes())
		return writeErr
	}

	data, hasData := response["data"]
	if !hasData || data == nil {
		if w.headerWritten {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		_, writeErr := w.ResponseWriter.Write(w.buffer.Bytes())
		return writeErr
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		if w.headerWritten {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		_, writeErr := w.ResponseWriter.Write(w.buffer.Bytes())
		return writeErr
	}

	encryptedData, iv, err := w.cipher.EncryptToBase64(dataBytes)
	if err != nil {
		if w.headerWritten {
			w.ResponseWriter.WriteHeader(w.statusCode)
		}
		_, writeErr := w.ResponseWriter.Write(w.buffer.Bytes())
		return writeErr
	}

	response["data"] = encryptedData

	w.ResponseWriter.Header().Set(HeaderEncryptIV, iv)
	if w.headerWritten {
		w.ResponseWriter.WriteHeader(w.statusCode)
	}

	encryptedResponse, err := json.Marshal(response)
	if err != nil {
		_, writeErr := w.ResponseWriter.Write(w.buffer.Bytes())
		return writeErr
	}

	_, err = w.ResponseWriter.Write(encryptedResponse)
	return err
}

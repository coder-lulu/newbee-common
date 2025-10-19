// Copyright 2024 The NewBee Authors. All Rights Reserved.

package encryption

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/coder-lulu/newbee-common/middleware/errors"
	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/logging"
	"github.com/coder-lulu/newbee-common/utils/crypto"
)

type EncryptionPlugin struct {
	core   *framework.CoreServices
	config *framework.EncryptionConfig
	cipher *crypto.AESGCMCipher
	logger *logging.MiddlewareLogger
}

func NewEncryptionPlugin() framework.MiddlewarePlugin {
	return &EncryptionPlugin{}
}

func (p *EncryptionPlugin) Name() string {
	return "Encryption"
}

func (p *EncryptionPlugin) Priority() int {
	return 15
}

func (p *EncryptionPlugin) Init(core *framework.CoreServices) error {
	p.core = core
	p.config = core.Config.Encryption
	p.logger = logging.NewMiddlewareLogger("encryption")

	if p.config == nil || !p.config.Enabled {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("encryption config is missing or disabled").
			Build()
		p.logger.WithError(err).Error("encryption plugin initialization failed")
		return err
	}

	if p.config.Key == "" {
		err := errors.NewError(errors.CodeConfigError).
			WithMessage("encryption key is not configured").
			Build()
		p.logger.WithError(err).Error("encryption plugin initialization failed")
		return err
	}

	cipher, err := crypto.NewAESGCMCipherFromBase64(p.config.Key)
	if err != nil {
		encErr := errors.NewError(errors.CodeConfigError).
			WithMessage("failed to initialize encryption cipher").
			WithCause(err).
			Build()
		p.logger.WithError(encErr).Error("encryption plugin initialization failed")
		return encErr
	}
	p.cipher = cipher

	p.logger.Info("encryption plugin initialized successfully")
	return nil
}

func (p *EncryptionPlugin) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := p.logger.WithContext(r.Context()).WithRequest(r)

		if p.shouldSkip(r.URL.Path) {
			logger.Debug("encryption skipped for path")
			next(w, r)
			return
		}

		encryptEnabled := r.Header.Get(HeaderEncryptEnable)
		if !p.config.ForceEncrypt && encryptEnabled != "true" {
			logger.Debug("encryption not requested")
			next(w, r)
			return
		}

		if r.Method != http.MethodGet && r.Body != nil {
			if err := p.decryptRequest(r, logger); err != nil {
				encErr := errors.NewError(errors.CodeDecryptionFailed).
					WithMessage("failed to decrypt request").
					WithCause(err).
					Build()
				logger.WithError(encErr).Error("request decryption failed")
				encErr.WriteHTTPResponse(w)
				return
			}
		}

		encryptedWriter := newEncryptedResponseWriter(w, p.cipher)

		next(encryptedWriter, r)

		if err := encryptedWriter.Flush(); err != nil {
			logger.WithError(err).Error("failed to flush encrypted response")
		}
	}
}

func (p *EncryptionPlugin) shouldSkip(path string) bool {
	for _, skipPath := range p.config.SkipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (p *EncryptionPlugin) decryptRequest(r *http.Request, logger *logging.MiddlewareLogger) error {
	ivHeader := r.Header.Get(HeaderEncryptIV)
	if ivHeader == "" {
		logger.Warn("encryption IV missing in request header")
		return errors.NewError(errors.CodeBadRequest).
			WithMessage("encryption IV is required").
			Build()
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	if len(bodyBytes) == 0 {
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return nil
	}

	decrypted, err := p.cipher.DecryptFromBase64(string(bodyBytes), ivHeader)
	if err != nil {
		return err
	}

	r.Body = io.NopCloser(bytes.NewReader(decrypted))
	r.ContentLength = int64(len(decrypted))

	logger.WithField("original_size", len(bodyBytes)).
		WithField("decrypted_size", len(decrypted)).
		Debug("request decrypted successfully")

	return nil
}

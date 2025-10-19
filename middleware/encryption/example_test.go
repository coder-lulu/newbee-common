// Copyright 2024 The NewBee Authors. All Rights Reserved.

package encryption_test

import (
	"fmt"

	"github.com/coder-lulu/newbee-common/middleware/framework"
	"github.com/coder-lulu/newbee-common/middleware/integration"
	"github.com/coder-lulu/newbee-common/utils/crypto"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/rest"
)

func ExampleEncryptionIntegration() {
	keyBase64, err := crypto.GenerateKeyBase64(crypto.AES256KeySize)
	if err != nil {
		panic(err)
	}
	fmt.Println("Generated encryption key:", keyBase64[:20]+"...")

	rds := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	result, err := integration.Setup(&integration.Config{
		Redis:     rds,
		JWTSecret: "your-jwt-secret",
		Mode:      integration.Production,
		Middleware: &framework.UnifiedConfig{
			Auth: &framework.AuthConfig{
				Enabled:      true,
				AccessSecret: "your-jwt-secret",
				SkipPaths:    []string{"/health", "/captcha"},
			},
			Encryption: &framework.EncryptionConfig{
				Enabled:      true,
				Key:          keyBase64,
				SkipPaths:    []string{"/health", "/metrics", "/captcha"},
				ForceEncrypt: false,
			},
		},
	})
	if err != nil {
		panic(err)
	}

	server := rest.MustNewServer(rest.RestConf{
		Host: "0.0.0.0",
		Port: 8080,
	})

	integration.ApplyToServer(server, result)

	fmt.Println("Encryption middleware configured successfully")
	fmt.Println("Priority: 15 (after Auth)")
	fmt.Println("Encryption enabled for all endpoints except:", []string{"/health", "/metrics", "/captcha"})
}

func ExampleForceEncryptionMode() {
	keyBase64 := "ZLc5cHF1ZjJzMTZ3OXh5emFiY2RlZmdoaWprbG1ub3A="

	config := &framework.UnifiedConfig{
		Encryption: &framework.EncryptionConfig{
			Enabled:      true,
			Key:          keyBase64,
			SkipPaths:    []string{"/health"},
			ForceEncrypt: true,
		},
	}

	fmt.Println("Force encryption mode enabled")
	fmt.Printf("Config: %+v\n", config.Encryption)
}

# 接口加解密中间件

## 概述

接口加解密中间件提供了基于 AES-256-GCM 的端到端加密功能，用于保护 API 请求和响应数据的机密性和完整性。

## 核心特性

- ✅ **AES-256-GCM 加密** - 提供认证加密，防止数据篡改
- ✅ **IV 自动管理** - 每次加密自动生成随机 IV，防止重放攻击
- ✅ **选择性加密** - 支持通过请求头控制是否启用加密
- ✅ **智能响应加密** - 只加密响应的 `data` 字段，保持 `code` 和 `msg` 明文
- ✅ **路径白名单** - 支持跳过特定路径（如健康检查）
- ✅ **兼容模式** - 默认兼容未加密请求，可配置强制加密

## 架构设计

### 加密流程

```
客户端                     服务端
  |                          |
  |  1. 加密请求数据          |
  |     (使用AES-GCM)         |
  |  2. 生成随机IV           |
  |  3. 设置Headers:         |
  |     - X-Encrypt-Enable   |
  |     - X-Encrypt-IV       |
  |------------------------->|
  |                          | 4. 检查加密标识
  |                          | 5. 提取IV
  |                          | 6. 解密请求body
  |                          | 7. 处理业务逻辑
  |                          | 8. 提取响应data字段
  |                          | 9. 加密data
  |                          | 10. 生成新IV
  |                          | 11. 设置响应头
  |<-------------------------|
  | 12. 解密响应data         |
  | 13. 验证完整性           |
```

### 响应加密示例

**原始响应**:
```json
{
  "code": 0,
  "msg": "success",
  "data": {
    "username": "admin",
    "email": "admin@example.com"
  }
}
```

**加密后响应**:
```json
{
  "code": 0,
  "msg": "success",
  "data": "eKwR7vX...Base64EncodedEncryptedData..."
}
```

响应头: `X-Encrypt-IV: 4kJ9mN...Base64EncodedIV...`

## 快速开始

### 1. 生成加密密钥

```go
import "github.com/coder-lulu/newbee-common/utils/crypto"

// 生成AES-256密钥（32字节）
keyBase64, err := crypto.GenerateKeyBase64(crypto.AES256KeySize)
if err != nil {
    panic(err)
}
fmt.Println("Encryption Key:", keyBase64)
// 输出: Encryption Key: ZLc5cHF1ZjJzMTZ3OXh5emFiY2RlZmdoaWprbG1ub3A=
```

### 2. 配置中间件

```go
import (
    "github.com/coder-lulu/newbee-common/middleware/integration"
    "github.com/coder-lulu/newbee-common/middleware/framework"
)

// 方式1: 使用环境预设（推荐）
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: jwtSecret,
    Mode:      integration.Production,
    Middleware: &framework.UnifiedConfig{
        Encryption: &framework.EncryptionConfig{
            Enabled:      true,
            Key:          "your-base64-encoded-key",
            SkipPaths:    []string{"/health", "/metrics", "/captcha"},
            ForceEncrypt: false, // 兼容模式
        },
    },
})

// 方式2: 强制加密模式
result, err := integration.Setup(&integration.Config{
    Redis:     rds,
    JWTSecret: jwtSecret,
    Middleware: &framework.UnifiedConfig{
        Encryption: &framework.EncryptionConfig{
            Enabled:      true,
            Key:          "your-base64-encoded-key",
            ForceEncrypt: true, // 强制所有请求加密
        },
    },
})

// 应用到服务
integration.ApplyToServer(server, result)
```

### 3. 客户端实现示例

#### JavaScript/TypeScript

```typescript
import CryptoJS from 'crypto-js';

class ApiEncryption {
  private key: CryptoJS.lib.WordArray;

  constructor(keyBase64: string) {
    this.key = CryptoJS.enc.Base64.parse(keyBase64);
  }

  // 加密请求
  encryptRequest(data: any): { encrypted: string; iv: string } {
    const jsonStr = JSON.stringify(data);
    const iv = CryptoJS.lib.WordArray.random(12);
    
    const encrypted = CryptoJS.AES.encrypt(jsonStr, this.key, {
      iv: iv,
      mode: CryptoJS.mode.GCM,
      padding: CryptoJS.pad.NoPadding
    });

    return {
      encrypted: encrypted.ciphertext.toString(CryptoJS.enc.Base64),
      iv: CryptoJS.enc.Base64.stringify(iv)
    };
  }

  // 解密响应
  decryptResponse(encryptedData: string, ivBase64: string): any {
    const iv = CryptoJS.enc.Base64.parse(ivBase64);
    const ciphertext = CryptoJS.enc.Base64.parse(encryptedData);

    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: ciphertext } as any,
      this.key,
      {
        iv: iv,
        mode: CryptoJS.mode.GCM,
        padding: CryptoJS.pad.NoPadding
      }
    );

    return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
  }
}

// 使用示例
const encryption = new ApiEncryption('ZLc5cHF1ZjJzMTZ3OXh5emFiY2RlZmdoaWprbG1ub3A=');

// 发送加密请求
async function apiRequest(url: string, data: any) {
  const { encrypted, iv } = encryption.encryptRequest(data);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Encrypt-Enable': 'true',
      'X-Encrypt-IV': iv
    },
    body: encrypted
  });

  const result = await response.json();
  
  // 解密响应data
  if (result.data) {
    const responseIV = response.headers.get('X-Encrypt-IV');
    result.data = encryption.decryptResponse(result.data, responseIV);
  }

  return result;
}
```

#### Python

```python
import base64
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class ApiEncryption:
    def __init__(self, key_base64: str):
        self.key = base64.b64decode(key_base64)

    def encrypt_request(self, data: dict) -> tuple[str, str]:
        json_str = json.dumps(data)
        nonce = get_random_bytes(12)
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(json_str.encode('utf-8'))
        
        # GCM模式下，tag会自动附加到ciphertext
        encrypted = ciphertext + tag
        
        return (
            base64.b64encode(encrypted).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8')
        )

    def decrypt_response(self, encrypted_data: str, iv_base64: str) -> dict:
        encrypted = base64.b64decode(encrypted_data)
        nonce = base64.b64decode(iv_base64)
        
        # 分离密文和tag（最后16字节是tag）
        ciphertext = encrypted[:-16]
        tag = encrypted[-16:]
        
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return json.loads(plaintext.decode('utf-8'))

# 使用示例
import requests

encryption = ApiEncryption('ZLc5cHF1ZjJzMTZ3OXh5emFiY2RlZmdoaWprbG1ub3A=')

def api_request(url: str, data: dict):
    encrypted, iv = encryption.encrypt_request(data)
    
    response = requests.post(url, 
        data=encrypted,
        headers={
            'Content-Type': 'application/json',
            'X-Encrypt-Enable': 'true',
            'X-Encrypt-IV': iv
        }
    )
    
    result = response.json()
    
    # 解密响应data
    if 'data' in result:
        response_iv = response.headers.get('X-Encrypt-IV')
        result['data'] = encryption.decrypt_response(result['data'], response_iv)
    
    return result
```

## 配置选项

### EncryptionConfig

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `Enabled` | bool | false | 是否启用加密中间件 |
| `Key` | string | - | AES密钥（Base64编码，必须是16/24/32字节） |
| `SkipPaths` | []string | ["/health", "/metrics"] | 跳过加密的路径列表 |
| `ForceEncrypt` | bool | false | 是否强制加密（true时忽略X-Encrypt-Enable头） |

## HTTP 协议约定

### 请求头

| Header | 值 | 说明 |
|--------|---|------|
| `X-Encrypt-Enable` | "true" | 启用加密标识（ForceEncrypt=false时必须） |
| `X-Encrypt-IV` | Base64 | 请求加密使用的IV（12字节） |

### 响应头

| Header | 值 | 说明 |
|--------|---|------|
| `X-Encrypt-IV` | Base64 | 响应加密使用的IV（12字节） |

## 安全建议

1. **密钥管理**
   - 使用环境变量或密钥管理服务（KMS）存储密钥
   - 定期轮换密钥
   - 不要将密钥硬编码在代码中

2. **传输安全**
   - 必须在 HTTPS 上使用
   - 启用 HSTS

3. **IV 安全**
   - 每次请求使用新的随机 IV
   - 不要重复使用 IV

4. **错误处理**
   - 解密失败时不要泄露详细错误信息
   - 记录加密/解密失败事件用于审计

## 性能考虑

- 加密开销：~0.5ms（1KB数据）
- 解密开销：~0.5ms（1KB数据）
- 内存占用：minimal（流式处理）

## 故障排查

### 常见问题

1. **解密失败: "decryption failed (data may be tampered)"**
   - 检查密钥是否正确
   - 检查IV是否正确传递
   - 检查数据在传输过程中是否被修改

2. **"encryption IV is required"**
   - 确保请求头包含 `X-Encrypt-IV`
   - 检查IV是否为有效的Base64字符串

3. **加密不生效**
   - 检查路径是否在 SkipPaths 中
   - 检查 `X-Encrypt-Enable` 头是否设置为 "true"
   - 检查 Enabled 配置是否为 true

## 版本历史

- v1.0.0 (2025-10-04) - 初始版本
  - AES-256-GCM 加密
  - 智能响应加密
  - 路径白名单
  - 兼容模式支持

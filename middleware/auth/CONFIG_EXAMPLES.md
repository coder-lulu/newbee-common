# 认证中间件安全配置示例

## 开发环境配置 (auth.dev.yaml)

```yaml
# 基础配置
enabled: true
skip_paths:
  - /health
  - /metrics
  - /ping
  - /api/v1/public/*

# 密钥管理（开发环境）
key_management:
  use_hsm: false
  encrypted_key: "" # 开发环境可使用自动生成
  key_derivation: true
  master_key_path: "" # 使用环境变量
  rotation_enabled: false # 开发环境可关闭
  rotation_interval: 24h
  grace_period: 1h
  algorithm: "HS256"
  min_key_length: 32

# Token配置
token_config:
  issuer: "newbee-dev"
  audience:
    - "newbee-api"
  expiration_time: 30m
  refresh_enabled: true
  refresh_time: 7d
  bind_to_ip: false # 开发环境可关闭
  bind_to_user_agent: false
  bind_to_fingerprint: false
  revocation_enabled: true
  blacklist_ttl: 24h

# 安全特性
security:
  validate_request_signature: false
  require_secure_transport: false # 开发环境允许HTTP
  prevent_replay: false
  nonce_window: 5m
  csrf_protection: true
  csrf_token_header: "X-CSRF-Token"
  max_concurrent_sessions: 10
  session_timeout: 24h
  idle_timeout: 2h
  mfa_enabled: false
  security_headers:
    X-Environment: "development"

# 速率限制
rate_limit:
  enabled: true
  requests_per_second: 1000
  burst_size: 100
  per_user_limit: 10000
  adaptive_enabled: false
  suspicious_threshold: 20

# 审计日志
audit:
  enabled: true
  log_level: "debug"
  log_successful_auth: true
  log_failed_auth: true
  log_token_operations: true
  log_suspicious_activity: true
  mask_sensitive_data: false # 开发环境可查看完整数据
  sensitive_fields:
    - password
    - token
```

## 测试环境配置 (auth.test.yaml)

```yaml
# 基础配置
enabled: true
skip_paths:
  - /health
  - /metrics

# 密钥管理（测试环境）
key_management:
  use_hsm: false
  encrypted_key: "${ENCRYPTED_JWT_KEY}" # 从环境变量读取
  key_derivation: true
  master_key_path: "/etc/newbee/keys/master.key"
  rotation_enabled: true
  rotation_interval: 72h
  grace_period: 2h
  algorithm: "HS384"
  min_key_length: 48

# Token配置
token_config:
  issuer: "newbee-test"
  audience:
    - "newbee-api"
    - "newbee-test"
  expiration_time: 20m
  refresh_enabled: true
  refresh_time: 3d
  bind_to_ip: true
  bind_to_user_agent: true
  bind_to_fingerprint: false
  revocation_enabled: true
  blacklist_ttl: 12h

# 安全特性
security:
  validate_request_signature: false
  require_secure_transport: true
  prevent_replay: true
  nonce_window: 5m
  csrf_protection: true
  csrf_token_header: "X-CSRF-Token"
  max_concurrent_sessions: 5
  session_timeout: 12h
  idle_timeout: 1h
  mfa_enabled: false
  security_headers:
    X-Environment: "testing"

# 速率限制
rate_limit:
  enabled: true
  requests_per_second: 500
  burst_size: 50
  per_user_limit: 5000
  adaptive_enabled: true
  suspicious_threshold: 10

# 审计日志
audit:
  enabled: true
  log_level: "info"
  log_successful_auth: true
  log_failed_auth: true
  log_token_operations: true
  log_suspicious_activity: true
  mask_sensitive_data: true
  sensitive_fields:
    - password
    - token
    - secret
    - key
    - ssn
    - credit_card
```

## 生产环境配置 (auth.prod.yaml)

```yaml
# 基础配置
enabled: true
skip_paths:
  - /health
  - /metrics

# 密钥管理（生产环境）
key_management:
  use_hsm: true # 推荐使用HSM
  encrypted_key: "" # 使用HSM时不需要
  key_derivation: true
  master_key_path: "" # 使用HSM
  rotation_enabled: true
  rotation_interval: 24h
  grace_period: 1h
  algorithm: "HS512" # 或 RS256 for RSA
  min_key_length: 64

# Token配置
token_config:
  issuer: "newbee-prod"
  audience:
    - "newbee-api"
    - "newbee-web"
    - "newbee-mobile"
  expiration_time: 15m
  refresh_enabled: true
  refresh_time: 7d
  bind_to_ip: true
  bind_to_user_agent: true
  bind_to_fingerprint: true
  revocation_enabled: true
  blacklist_ttl: 24h

# 安全特性
security:
  validate_request_signature: true # 高安全环境启用
  require_secure_transport: true
  prevent_replay: true
  nonce_window: 3m
  csrf_protection: true
  csrf_token_header: "X-CSRF-Token"
  max_concurrent_sessions: 3
  session_timeout: 8h
  idle_timeout: 30m
  mfa_enabled: true
  mfa_providers:
    - totp
    - sms
    - email
  security_headers:
    X-Environment: "production"
    Strict-Transport-Security: "max-age=63072000; includeSubDomains; preload"

# 速率限制
rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 10
  per_user_limit: 1000
  adaptive_enabled: true
  suspicious_threshold: 5

# 审计日志
audit:
  enabled: true
  log_level: "warn"
  log_successful_auth: true
  log_failed_auth: true
  log_token_operations: true
  log_suspicious_activity: true
  mask_sensitive_data: true
  sensitive_fields:
    - password
    - token
    - secret
    - key
    - ssn
    - credit_card
    - phone
    - email
    - address
```

## 环境变量配置示例

```bash
# 开发环境 (.env.development)
NEWBEE_ENV=development
NEWBEE_JWT_SECRET=dev-secret-key-change-in-production
NEWBEE_REDIS_URL=redis://localhost:6379/0
NEWBEE_LOG_LEVEL=debug

# 测试环境 (.env.test)
NEWBEE_ENV=test
NEWBEE_MASTER_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ENCRYPTED_JWT_KEY=base64_encrypted_key_here
NEWBEE_REDIS_URL=redis://test-redis:6379/0
NEWBEE_LOG_LEVEL=info

# 生产环境 (.env.production)
NEWBEE_ENV=production
NEWBEE_HSM_ENDPOINT=https://hsm.example.com
NEWBEE_HSM_KEY_ID=jwt-signing-key-prod
NEWBEE_HSM_API_KEY=${HSM_API_KEY}
NEWBEE_REDIS_CLUSTER=redis-cluster-1:6379,redis-cluster-2:6379,redis-cluster-3:6379
NEWBEE_LOG_LEVEL=warn
NEWBEE_SENTRY_DSN=https://xxx@sentry.io/xxx
```

## Docker Compose 配置示例

```yaml
version: '3.8'

services:
  api:
    image: newbee/api:latest
    environment:
      - NEWBEE_ENV=production
      - NEWBEE_CONFIG_PATH=/etc/newbee/auth.prod.yaml
    secrets:
      - jwt_key
      - hsm_api_key
    volumes:
      - ./config:/etc/newbee:ro
    networks:
      - internal
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - internal
    deploy:
      replicas: 1
      placement:
        constraints:
          - node.role == manager

secrets:
  jwt_key:
    external: true
  hsm_api_key:
    external: true

volumes:
  redis_data:

networks:
  internal:
    driver: overlay
    encrypted: true
```

## Kubernetes ConfigMap 示例

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: newbee
data:
  auth.yaml: |
    enabled: true
    skip_paths:
      - /health
      - /metrics
    # ... 其他配置
```

## Kubernetes Secret 示例

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
  namespace: newbee
type: Opaque
data:
  jwt-key: <base64_encoded_key>
  master-key: <base64_encoded_master_key>
  hsm-api-key: <base64_encoded_hsm_api_key>
```

## 安全最佳实践

### 1. 密钥管理
- **永远不要**在代码中硬编码密钥
- 使用环境变量或密钥管理服务
- 定期轮换密钥
- 使用不同环境的不同密钥

### 2. 配置管理
- 使用配置管理工具（Consul、etcd等）
- 加密敏感配置
- 版本控制配置文件（不包含密钥）
- 审计配置变更

### 3. 监控告警
- 监控认证失败率
- 设置异常行为告警
- 实时日志分析
- 定期安全审计

### 4. 部署安全
- 使用容器安全扫描
- 限制容器权限
- 网络隔离
- 定期更新依赖

## 故障排查

### 常见问题

1. **Token验证失败**
   - 检查密钥配置
   - 验证时钟同步
   - 查看审计日志

2. **性能问题**
   - 检查Redis连接
   - 优化密钥缓存
   - 调整速率限制

3. **安全告警**
   - 查看审计日志
   - 分析攻击模式
   - 调整安全策略

## 更新历史

- v1.0.0 (2024-01-24): 初始版本
- v1.1.0 (待定): 添加OAuth2支持
- v1.2.0 (待定): 添加SAML支持
// Copyright 2024 The NewBee Authors. All Rights Reserved.

package keys

// ContextKey represents a type-safe context key to prevent collisions.
// These keys are the SINGLE SOURCE OF TRUTH for ALL context operations in the system.
// DO NOT use direct string literals or go-zero enum keys - ALWAYS use these constants.
type ContextKey string

// String returns the string representation of the context key
func (k ContextKey) String() string {
	return string(k)
}

const (
	// Tenant Keys - 租户相关的Context键
	// 注意：这些值必须与现有系统兼容，因此保持与go-zero enum相同的值
	TenantIDKey ContextKey = "tenantId" // 与go-zero enum.TenantIdCtxKey兼容

	// Authentication Keys - 认证相关的Context键  
	UserIDKey    ContextKey = "userId"    // 与go-zero enum.UserIdRpcCtxKey兼容
	UsernameKey  ContextKey = "username"  // 用户名，无enum对应
	RoleCodesKey ContextKey = "roleCodes" // 角色编码，与enum.RoleIdRpcCtxKey兼容
	DeptIDKey    ContextKey = "deptId"    // 部门ID，与enum.DepartmentIdRpcCtxKey兼容

	// User Profile Keys - 额外的用户信息
	NicknameKey ContextKey = "nickname" // 用户昵称
	AvatarKey   ContextKey = "avatar"   // 用户头像URL

	// Data Permission Keys
	DataScopeKey ContextKey = "dataScope" // 保持原值，无enum对应

	// Tracing & Other Keys
	RequestIDKey ContextKey = "requestId" // 保持原值，无enum对应
	TraceIDKey   ContextKey = "traceId"   // 保持原值，无enum对应
	
	// System Context Keys - 系统级操作标识
	SystemContextKey ContextKey = "systemContext" // 系统上下文标识
	PublicAccessKey  ContextKey = "publicAccess"  // 公共访问标识
)

// JWT Token Field Names - JWT token中的字段名（优化长度）
// 这些是JWT payload中实际使用的字段名，尽可能短以减少token长度
const (
	// 核心认证字段 - 必需
	JWTUserID   = "uid"  // 用户ID - 对应UserIDKey
	JWTTenantID = "tid"  // 租户ID - 对应TenantIDKey  
	JWTUsername = "un"   // 用户名 - 对应UsernameKey
	JWTDeptID   = "did"  // 部门ID - 对应DeptIDKey
	
	// 权限相关字段 - 必需
	JWTRoleCodes = "rc"  // 角色编码 - 对应RoleCodesKey
	
	// 用户信息字段 - 可选，根据需要包含
	JWTNickname = "nn"   // 昵称 - 对应NicknameKey
	JWTAvatar   = "av"   // 头像 - 对应AvatarKey
	
	// 系统字段 - JWT标准字段，无需映射
	// "exp" - 过期时间 (标准JWT字段)
	// "iat" - 签发时间 (标准JWT字段)
)

// GetContextKey returns the standard context key for the given name
// This function helps maintain consistency across the codebase
func GetContextKey(name string) ContextKey {
	switch name {
	case "tenant", "tenantId", "tenant-id":
		return TenantIDKey
	case "user", "userId", "user-id":
		return UserIDKey
	case "username":
		return UsernameKey  
	case "role", "roleCodes", "role-id":
		return RoleCodesKey
	case "dept", "deptId", "dept-id":
		return DeptIDKey
	case "dataScope":
		return DataScopeKey
	case "nickname":
		return NicknameKey
	case "avatar":
		return AvatarKey
	case "requestId":
		return RequestIDKey
	case "traceId":
		return TraceIDKey
	case "systemContext":
		return SystemContextKey
	case "publicAccess":
		return PublicAccessKey
	default:
		// 对于未知的key，返回原值作为ContextKey
		return ContextKey(name)
	}
}

// IsStandardKey checks if the given key is a standard context key
func IsStandardKey(key string) bool {
	standardKeys := []string{
		string(TenantIDKey), string(UserIDKey), string(UsernameKey),
		string(RoleCodesKey), string(DeptIDKey), string(DataScopeKey),
		string(NicknameKey), string(AvatarKey), string(RequestIDKey), string(TraceIDKey),
		string(SystemContextKey), string(PublicAccessKey),
	}
	
	for _, standardKey := range standardKeys {
		if key == standardKey {
			return true
		}
	}
	return false
}

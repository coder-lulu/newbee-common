// Copyright 2023 The Ryan SU Authors (https://github.com/suyuan32). All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rolectx

import (
    "context"
    "slices"
    "strings"
    "fmt"

    "github.com/coder-lulu/newbee-common/middleware/keys"
    "github.com/zeromicro/go-zero/core/logx"
    "google.golang.org/grpc/metadata"
)

// GetRoleIDFromCtx returns role id from context.
func GetRoleIDFromCtx(ctx context.Context) ([]string, error) {
    // prefer unified keys manager
    if roleId, ok := ctx.Value(keys.RoleCodesKey).(string); !ok {
        // fallback to legacy key
        if rid, ok2 := ctx.Value("roleId").(string); ok2 {
            roleIds := strings.Split(rid, ",")
            slices.Sort(roleIds)
            return roleIds, nil
        }
        if md, ok := metadata.FromIncomingContext(ctx); !ok {
            logx.Error("failed to get role id from context", logx.Field("detail", ctx))
            return nil, fmt.Errorf("invalid argument: failed to get role id from context")
        } else {
            // use unified metadata key, fallback legacy header name
            var val string
            if data := md.Get(keys.RoleCodesKey.String()); len(data) > 0 {
                val = data[0]
            } else if data := md.Get("roleId"); len(data) > 0 { // legacy
                val = data[0]
            }
            if val != "" {
                roleIds := strings.Split(val, ",")
                slices.Sort(roleIds)
                return roleIds, nil
            } else {
                return nil, fmt.Errorf("invalid argument: failed to get role id from context")
            }
        }
    } else {
        roleIds := strings.Split(roleId, ",")
        slices.Sort(roleIds)
        return roleIds, nil
    }
}

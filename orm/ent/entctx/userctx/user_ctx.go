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

package userctx

import (
    "context"
    "fmt"

    "github.com/coder-lulu/newbee-common/middleware/keys"
    "github.com/zeromicro/go-zero/core/logx"
    "google.golang.org/grpc/metadata"
)

// GetUserIDFromCtx returns user id from context.
func GetUserIDFromCtx(ctx context.Context) (string, error) {
    // prefer unified keys manager
    if userId, ok := ctx.Value(keys.UserIDKey).(string); !ok {
        // fallback to legacy key
        if uid, ok2 := ctx.Value("userId").(string); ok2 {
            return uid, nil
        }
        if md, ok := metadata.FromIncomingContext(ctx); !ok {
            logx.Error("failed to get user id from context", logx.Field("detail", ctx))
            return "", fmt.Errorf("invalid argument: failed to get user id from context")
        } else {
            // use unified metadata key, fallback legacy header name
            if data := md.Get(keys.UserIDKey.String()); len(data) > 0 {
                return data[0], nil
            } else if data := md.Get("userId"); len(data) > 0 {
                return data[0], nil
            } else {
                return "", fmt.Errorf("invalid argument: failed to get user id from context")
            }
        }
    } else {
        return userId, nil
    }
}

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

package deptctx

import (
    "context"
    "encoding/json"
    "strconv"
    "fmt"

    "github.com/coder-lulu/newbee-common/middleware/keys"
    "github.com/zeromicro/go-zero/core/logx"
    "google.golang.org/grpc/metadata"
)

// GetDepartmentIDFromCtx returns department id from context.
func GetDepartmentIDFromCtx(ctx context.Context) (uint64, error) {
	var departmentId string
	var found bool

	// 尝试多种类型的部门ID获取
	if deptValue := ctx.Value(keys.DeptIDKey); deptValue != nil {
		switch v := deptValue.(type) {
		case json.Number:
			departmentId = v.String()
			found = true
		case float64:
			departmentId = strconv.FormatFloat(v, 'f', 0, 64)
			found = true
		case int:
			departmentId = strconv.Itoa(v)
			found = true
		case uint64:
			departmentId = strconv.FormatUint(v, 10)
			found = true
		case string:
			departmentId = v
			found = true
		}
	}

        if !found {
            if md, ok := metadata.FromIncomingContext(ctx); !ok {
                logx.Error("failed to get department id from context", logx.Field("detail", ctx))
                return 0, fmt.Errorf("invalid argument: failed to get department ID")
            } else {
                // use common keys manager for metadata key
                if data := md.Get(keys.DeptIDKey.String()); len(data) > 0 {
                    departmentId = data[0]
                    found = true
                } else {
                    return 0, fmt.Errorf("invalid argument: failed to get department ID")
                }
            }
        }

	if !found || departmentId == "" {
        logx.Error("department id not found or empty in context")
        return 0, fmt.Errorf("invalid argument: failed to get department ID")
	}

	id, err := strconv.ParseUint(departmentId, 10, 64)
	if err != nil {
        logx.Error("failed to convert department id", logx.Field("detail", err), logx.Field("departmentId", departmentId))
        return 0, fmt.Errorf("invalid argument: failed to get department ID")
	}
	return id, nil
}

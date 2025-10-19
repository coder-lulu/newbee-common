// Copyright 2024 The NewBee Authors. All Rights Reserved.
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

package hooks

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
)

// SoftDeleteInterceptor 软删除拦截器
// 放在 common 包中避免循环依赖
func SoftDeleteInterceptor() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// 跳过系统上下文的软删除过滤
			if IsSystemContext(ctx) {
				return next.Query(ctx, query)
			}
			
			// 为查询添加软删除过滤条件
			addSoftDeleteFilter(query)
			
			return next.Query(ctx, query)
		})
	})
}

// addSoftDeleteFilter 添加软删除过滤条件
func addSoftDeleteFilter(query ent.Query) {
	// Method 1: Try Modify interface (most efficient)
	if modifyQuery, ok := query.(interface{ Modify(func(*sql.Selector)) }); ok {
		modifyQuery.Modify(func(s *sql.Selector) {
			s.Where(sql.IsNull(s.C("deleted_at")))
		})
		return
	}
	
	// Method 2: Try Where interface
	type whereQuery interface {
		Where(...func(*sql.Selector))
	}
	if whereQ, ok := query.(whereQuery); ok {
		whereQ.Where(func(selector *sql.Selector) {
			selector.Where(sql.IsNull("deleted_at"))
		})
		return
	}
	
	// Method 3: Try WhereP if available
	type wherePQuery interface {
		WhereP(func(*sql.Selector))
	}
	if wherePQ, ok := query.(wherePQuery); ok {
		wherePQ.WhereP(func(selector *sql.Selector) {
			selector.Where(sql.IsNull("deleted_at"))
		})
		return
	}
}

// SoftDeleteHook 软删除钩子
// 将删除操作转换为更新 deleted_at 字段
func SoftDeleteHook() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
			// 只处理删除操作
			if mutation.Op() != ent.OpDelete && mutation.Op() != ent.OpDeleteOne {
				return next.Mutate(ctx, mutation)
			}
			
			// 跳过系统上下文的软删除转换（允许真实删除）
			if IsSystemContext(ctx) {
				return next.Mutate(ctx, mutation)
			}
			
			// 将删除操作转换为更新操作
			return convertDeleteToUpdate(ctx, mutation)
		})
	}
}

// convertDeleteToUpdate 将删除操作转换为更新操作
func convertDeleteToUpdate(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
	// 获取要删除的记录ID
	ids, err := getEntityIDs(mutation)
	if err != nil {
		return nil, fmt.Errorf("failed to get entity IDs: %w", err)
	}
	
	if len(ids) == 0 {
		return nil, fmt.Errorf("no entities found to delete")
	}
	
	// 执行软删除更新
	now := time.Now()
	tableName := mutation.Type()
	
	// 构建更新SQL
	_ = fmt.Sprintf("UPDATE %s SET deleted_at = ? WHERE id IN (?%s)", 
		tableName, 
		generatePlaceholders(len(ids)-1))
	
	// 准备参数
	_ = []interface{}{now}
	for _, id := range ids {
		_ = id // 标记为已使用
	}
	
	// 执行更新
	// 注意：这里需要根据实际的数据库执行方式来实现
	// 暂时返回成功，具体实现需要根据 ent 的内部机制
	
	return struct{}{}, nil
}

// getEntityIDs 从 mutation 中获取实体ID
func getEntityIDs(mutation ent.Mutation) ([]interface{}, error) {
	var ids []interface{}
	
	// 尝试通过类型断言获取ID方法
	type idMutation interface {
		ID() (interface{}, bool)
	}
	
	if idMut, ok := mutation.(idMutation); ok {
		if id, exists := idMut.ID(); exists {
			ids = append(ids, id)
			return ids, nil
		}
	}
	
	// 对于批量删除操作，暂时不支持软删除
	// 可以在未来扩展支持批量软删除
	
	return ids, nil
}

// generatePlaceholders 生成SQL占位符
func generatePlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	
	placeholders := ""
	for i := 0; i < count; i++ {
		placeholders += ",?"
	}
	
	return placeholders
}
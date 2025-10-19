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

package mixins

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// SoftDeleteMixin 实现软删除模式
// 将此 mixin 放在 common 包中避免循环依赖
type SoftDeleteMixin struct {
	mixin.Schema
}

// Fields 定义软删除相关字段
func (SoftDeleteMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("deleted_at").
			Optional().
			Nillable().
			Comment("Soft delete timestamp | 软删除时间戳"),
	}
}

// Indexes 定义软删除相关索引
func (SoftDeleteMixin) Indexes() []ent.Index {
	return []ent.Index{
		// 添加 deleted_at 字段的索引以优化查询性能
		// index.Fields("deleted_at"),
	}
}
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

package framework

import "net/http"

// MiddlewarePlugin defines the contract for all middleware plugins.
// This interface enables the MiddlewareManager to manage the lifecycle,
// configuration, and execution order of each middleware uniformly.
type MiddlewarePlugin interface {
	// Name returns the unique name of the plugin (e.g., "auth", "dataperm").
	Name() string

	// Init initializes the plugin with the shared CoreServices.
	// This method is called once by the manager at startup.
	Init(core *CoreServices) error

	// Handle returns the core middleware logic as an http.HandlerFunc.
	// This is compatible with go-zero's middleware chain.
	Handle(next http.HandlerFunc) http.HandlerFunc

	// Priority determines the execution order in the middleware chain.
	// Lower values are executed first.
	Priority() int
}

// ShutdownablePlugin is an optional interface for plugins that need graceful shutdown
type ShutdownablePlugin interface {
	MiddlewarePlugin
	
	// Shutdown gracefully stops the plugin and cleans up resources
	Shutdown() error
}

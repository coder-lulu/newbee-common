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

import (
	"fmt"
	"sort"
	"sync"
)

// DependencyGraph manages plugin dependencies and execution order
type DependencyGraph struct {
	nodes   map[string]*GraphNode
	edges   map[string][]string // adjacency list: node -> dependencies
	reverse map[string][]string // reverse edges: node -> dependents
	mu      sync.RWMutex
}

// GraphNode represents a node in the dependency graph
type GraphNode struct {
	Name         string
	Dependencies []string
	Dependents   []string
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes:   make(map[string]*GraphNode),
		edges:   make(map[string][]string),
		reverse: make(map[string][]string),
	}
}

// AddNode adds a node with its dependencies to the graph
func (dg *DependencyGraph) AddNode(name string, dependencies []string) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	// Create or update node
	node := &GraphNode{
		Name:         name,
		Dependencies: make([]string, len(dependencies)),
		Dependents:   make([]string, 0),
	}
	copy(node.Dependencies, dependencies)

	dg.nodes[name] = node

	// Update edges
	dg.edges[name] = make([]string, len(dependencies))
	copy(dg.edges[name], dependencies)

	// Update reverse edges
	for _, dep := range dependencies {
		if _, exists := dg.reverse[dep]; !exists {
			dg.reverse[dep] = make([]string, 0)
		}

		// Check if already exists to avoid duplicates
		found := false
		for _, dependent := range dg.reverse[dep] {
			if dependent == name {
				found = true
				break
			}
		}

		if !found {
			dg.reverse[dep] = append(dg.reverse[dep], name)
		}
	}

	// Update dependents in nodes
	for _, dep := range dependencies {
		if depNode, exists := dg.nodes[dep]; exists {
			// Check if already exists
			found := false
			for _, dependent := range depNode.Dependents {
				if dependent == name {
					found = true
					break
				}
			}

			if !found {
				depNode.Dependents = append(depNode.Dependents, name)
			}
		}
	}
}

// RemoveNode removes a node from the graph
func (dg *DependencyGraph) RemoveNode(name string) {
	dg.mu.Lock()
	defer dg.mu.Unlock()

	node, exists := dg.nodes[name]
	if !exists {
		return
	}

	// Remove from dependencies of other nodes
	for _, dependent := range node.Dependents {
		if depNode, exists := dg.nodes[dependent]; exists {
			// Remove from dependencies
			newDeps := make([]string, 0, len(depNode.Dependencies))
			for _, dep := range depNode.Dependencies {
				if dep != name {
					newDeps = append(newDeps, dep)
				}
			}
			depNode.Dependencies = newDeps

			// Update edges
			dg.edges[dependent] = newDeps
		}
	}

	// Remove from dependents of dependency nodes
	for _, dep := range node.Dependencies {
		if depNode, exists := dg.nodes[dep]; exists {
			// Remove from dependents
			newDeps := make([]string, 0, len(depNode.Dependents))
			for _, dependent := range depNode.Dependents {
				if dependent != name {
					newDeps = append(newDeps, dependent)
				}
			}
			depNode.Dependents = newDeps
		}

		// Remove from reverse edges
		if reverseEdges, exists := dg.reverse[dep]; exists {
			newReverse := make([]string, 0, len(reverseEdges))
			for _, dependent := range reverseEdges {
				if dependent != name {
					newReverse = append(newReverse, dependent)
				}
			}
			dg.reverse[dep] = newReverse
		}
	}

	// Remove node itself
	delete(dg.nodes, name)
	delete(dg.edges, name)
	delete(dg.reverse, name)
}

// GetDependents returns all nodes that depend on the given node
func (dg *DependencyGraph) GetDependents(name string) []string {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	if dependents, exists := dg.reverse[name]; exists {
		result := make([]string, len(dependents))
		copy(result, dependents)
		return result
	}

	return []string{}
}

// GetDependencies returns all dependencies of the given node
func (dg *DependencyGraph) GetDependencies(name string) []string {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	if deps, exists := dg.edges[name]; exists {
		result := make([]string, len(deps))
		copy(result, deps)
		return result
	}

	return []string{}
}

// DetectCycles detects circular dependencies in the graph
func (dg *DependencyGraph) DetectCycles() error {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	visited := make(map[string]bool)
	recStack := make(map[string]bool)

	for node := range dg.nodes {
		if !visited[node] {
			if cycle := dg.detectCyclesDFS(node, visited, recStack, []string{}); cycle != nil {
				return fmt.Errorf("circular dependency detected: %v", cycle)
			}
		}
	}

	return nil
}

// TopologicalSort returns nodes in topologically sorted order
func (dg *DependencyGraph) TopologicalSort() ([]string, error) {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	// Check for cycles first
	if err := dg.DetectCycles(); err != nil {
		return nil, err
	}

	visited := make(map[string]bool)
	stack := make([]string, 0)

	// DFS for topological sort
	var dfs func(string)
	dfs = func(node string) {
		visited[node] = true

		// Visit all dependencies first
		if deps, exists := dg.edges[node]; exists {
			for _, dep := range deps {
				if !visited[dep] {
					dfs(dep)
				}
			}
		}

		stack = append(stack, node)
	}

	// Visit all nodes
	for node := range dg.nodes {
		if !visited[node] {
			dfs(node)
		}
	}

	return stack, nil
}

// GetExecutionOrder returns the execution order for plugins
// This is similar to topological sort but considers priority within dependency constraints
func (dg *DependencyGraph) GetExecutionOrder() ([]string, error) {
	// For now, just return topological sort
	// In the future, this could be enhanced to consider plugin priorities
	return dg.TopologicalSort()
}

// GetStartOrder returns the order in which nodes should be started
func (dg *DependencyGraph) GetStartOrder() ([]string, error) {
	return dg.TopologicalSort()
}

// GetStopOrder returns the order in which nodes should be stopped (reverse of start order)
func (dg *DependencyGraph) GetStopOrder() ([]string, error) {
	startOrder, err := dg.GetStartOrder()
	if err != nil {
		return nil, err
	}

	// Reverse the order
	stopOrder := make([]string, len(startOrder))
	for i, j := 0, len(startOrder)-1; i < len(startOrder); i, j = i+1, j-1 {
		stopOrder[i] = startOrder[j]
	}

	return stopOrder, nil
}

// GetAllNodes returns all nodes in the graph
func (dg *DependencyGraph) GetAllNodes() []string {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	nodes := make([]string, 0, len(dg.nodes))
	for name := range dg.nodes {
		nodes = append(nodes, name)
	}

	sort.Strings(nodes)
	return nodes
}

// GetNodeInfo returns information about a specific node
func (dg *DependencyGraph) GetNodeInfo(name string) (*GraphNode, bool) {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	if node, exists := dg.nodes[name]; exists {
		// Return a copy to avoid race conditions
		result := &GraphNode{
			Name:         node.Name,
			Dependencies: make([]string, len(node.Dependencies)),
			Dependents:   make([]string, len(node.Dependents)),
		}
		copy(result.Dependencies, node.Dependencies)
		copy(result.Dependents, node.Dependents)
		return result, true
	}

	return nil, false
}

// Validate validates the integrity of the dependency graph
func (dg *DependencyGraph) Validate() error {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	// Check that all dependencies exist
	for nodeName, deps := range dg.edges {
		for _, dep := range deps {
			if _, exists := dg.nodes[dep]; !exists {
				return fmt.Errorf("node %s has non-existent dependency: %s", nodeName, dep)
			}
		}
	}

	// Check that reverse edges are consistent
	for nodeName, dependents := range dg.reverse {
		for _, dependent := range dependents {
			if deps, exists := dg.edges[dependent]; exists {
				found := false
				for _, dep := range deps {
					if dep == nodeName {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("inconsistent reverse edge: %s -> %s", nodeName, dependent)
				}
			}
		}
	}

	return nil
}

// Clone creates a deep copy of the dependency graph
func (dg *DependencyGraph) Clone() *DependencyGraph {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	clone := NewDependencyGraph()

	// Copy nodes
	for name, node := range dg.nodes {
		cloneNode := &GraphNode{
			Name:         node.Name,
			Dependencies: make([]string, len(node.Dependencies)),
			Dependents:   make([]string, len(node.Dependents)),
		}
		copy(cloneNode.Dependencies, node.Dependencies)
		copy(cloneNode.Dependents, node.Dependents)
		clone.nodes[name] = cloneNode
	}

	// Copy edges
	for node, deps := range dg.edges {
		clone.edges[node] = make([]string, len(deps))
		copy(clone.edges[node], deps)
	}

	// Copy reverse edges
	for node, dependents := range dg.reverse {
		clone.reverse[node] = make([]string, len(dependents))
		copy(clone.reverse[node], dependents)
	}

	return clone
}

// Private methods

func (dg *DependencyGraph) detectCyclesDFS(node string, visited, recStack map[string]bool, path []string) []string {
	visited[node] = true
	recStack[node] = true
	path = append(path, node)

	if deps, exists := dg.edges[node]; exists {
		for _, dep := range deps {
			if !visited[dep] {
				if cycle := dg.detectCyclesDFS(dep, visited, recStack, path); cycle != nil {
					return cycle
				}
			} else if recStack[dep] {
				// Found cycle - return the cycle path
				cycleStart := -1
				for i, p := range path {
					if p == dep {
						cycleStart = i
						break
					}
				}
				if cycleStart >= 0 {
					cycle := make([]string, len(path)-cycleStart+1)
					copy(cycle, path[cycleStart:])
					cycle[len(cycle)-1] = dep // close the cycle
					return cycle
				}
			}
		}
	}

	recStack[node] = false
	return nil
}

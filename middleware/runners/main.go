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

package runners

import (
	"flag"
	"log"
	"time"
)

func main() {
	var (
		testRunner   = flag.String("runner", "l1cache", "Test runner: l1cache, optimized, performance")
		testType     = flag.String("test", "comparison", "Test type")
		duration     = flag.Duration("duration", 60*time.Second, "Test duration")
		warmup       = flag.Duration("warmup", 10*time.Second, "Warmup duration")
		concurrency  = flag.Int("concurrency", 100, "Number of concurrent goroutines")
		cacheHitRate = flag.Float64("hit-rate", 0.8, "Expected cache hit rate for simulation")
		output       = flag.String("output", "console", "Output format: console, json")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	switch *testRunner {
	case "l1cache":
		RunL1CachePerfTest(*testType, *duration, *warmup, *concurrency, *cacheHitRate)
	case "optimized":
		RunOptimizedPerfTest(*testType, *duration, *warmup)
	case "performance":
		RunPerformanceTest(*testType, *duration, *warmup, *output)
	default:
		log.Fatalf("Unknown test runner: %s", *testRunner)
	}
}
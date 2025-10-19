// Copyright 2024 The NewBee Authors. All Rights Reserved.

package util

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
)

// StreamingBodyReader 流式请求体读取器
// 用于安全地读取HTTP请求体，支持大小限制、哈希计算和采样
type StreamingBodyReader struct {
	reader     io.Reader
	maxSize    int64
	readSize   int64
	hash       hash.Hash
	sample     []byte
	sampleSize int
}

// NewStreamingBodyReader 创建新的流式请求体读取器
func NewStreamingBodyReader(reader io.Reader, maxSize int64) *StreamingBodyReader {
	return &StreamingBodyReader{
		reader:     reader,
		maxSize:    maxSize,
		hash:       md5.New(),
		sampleSize: 512, // 只采样前512字节
	}
}

// NewStreamingBodyReaderWithSampleSize 创建带自定义采样大小的流式请求体读取器
func NewStreamingBodyReaderWithSampleSize(reader io.Reader, maxSize int64, sampleSize int) *StreamingBodyReader {
	return &StreamingBodyReader{
		reader:     reader,
		maxSize:    maxSize,
		hash:       md5.New(),
		sampleSize: sampleSize,
	}
}

// Read 实现io.Reader接口
func (s *StreamingBodyReader) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if n > 0 {
		s.readSize += int64(n)
		
		// 检查大小限制
		if s.readSize > s.maxSize {
			return 0, fmt.Errorf("request body too large: %d bytes (max: %d)", s.readSize, s.maxSize)
		}
		
		// 计算hash用于完整性检查
		s.hash.Write(p[:n])
		
		// 采样数据用于审计（只保存前面部分）
		if len(s.sample) < s.sampleSize {
			remaining := s.sampleSize - len(s.sample)
			if n > remaining {
				s.sample = append(s.sample, p[:remaining]...)
			} else {
				s.sample = append(s.sample, p[:n]...)
			}
		}
	}
	return n, err
}

// GetSummary 获取读取摘要信息
func (s *StreamingBodyReader) GetSummary() *BodySummary {
	return &BodySummary{
		TotalSize: s.readSize,
		Hash:      hex.EncodeToString(s.hash.Sum(nil)),
		Sample:    string(s.sample),
		Truncated: s.readSize > int64(s.sampleSize),
	}
}

// GetTotalSize 获取已读取的总大小
func (s *StreamingBodyReader) GetTotalSize() int64 {
	return s.readSize
}

// GetSample 获取采样数据
func (s *StreamingBodyReader) GetSample() []byte {
	return s.sample
}

// GetHash 获取当前的hash值
func (s *StreamingBodyReader) GetHash() string {
	return hex.EncodeToString(s.hash.Sum(nil))
}

// IsTruncated 检查是否被截断
func (s *StreamingBodyReader) IsTruncated() bool {
	return s.readSize > int64(s.sampleSize)
}

// BodySummary 请求体摘要信息
type BodySummary struct {
	TotalSize int64  `json:"total_size"`
	Hash      string `json:"hash"`
	Sample    string `json:"sample"`
	Truncated bool   `json:"truncated"`
}

// LimitedReader 实现带大小限制的Reader
type LimitedReader struct {
	reader   io.Reader
	maxSize  int64
	readSize int64
}

// NewLimitedReader 创建带大小限制的Reader
func NewLimitedReader(reader io.Reader, maxSize int64) *LimitedReader {
	return &LimitedReader{
		reader:  reader,
		maxSize: maxSize,
	}
}

// Read 实现io.Reader接口，带大小限制
func (l *LimitedReader) Read(p []byte) (int, error) {
	n, err := l.reader.Read(p)
	if n > 0 {
		l.readSize += int64(n)
		if l.readSize > l.maxSize {
			return 0, fmt.Errorf("content too large: %d bytes (max: %d)", l.readSize, l.maxSize)
		}
	}
	return n, err
}

// GetReadSize 获取已读取大小
func (l *LimitedReader) GetReadSize() int64 {
	return l.readSize
}
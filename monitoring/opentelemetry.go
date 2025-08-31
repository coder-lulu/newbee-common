package monitoring

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type Tracer struct {
	tracer trace.Tracer
}

func NewTracer(serviceName string) *Tracer {
	tracer := otel.GetTracerProvider().Tracer(serviceName)
	return &Tracer{tracer: tracer}
}

func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

func InitOpenTelemetry(serviceName, collectorEndpoint string) (*trace.TracerProvider, error) {
	// 创建OTLP导出器
	exporter, err := otlptracegrpc.New(context.Background(),
		otlptracegrpc.WithEndpoint(collectorEndpoint),
		otlptracegrpc.WithInsecure(), // 生产环境应使用安全连接
	)
	if err != nil {
		log.Fatalf("Failed to create OTLP trace exporter: %v", err)
		return nil, err
	}

	// 创建追踪提供者
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithSampler(trace.AlwaysSample()),
	)

	// 设置全局追踪提供者
	otel.SetTracerProvider(tp)

	return tp, nil
}

// 优雅关闭追踪提供者
func ShutdownTracing(tp *trace.TracerProvider) {
	if tp != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}
}
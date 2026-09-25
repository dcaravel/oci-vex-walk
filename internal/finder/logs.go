package finder

import (
	"context"
	"log/slog"
	"sync"
)

// Route parser diagnostics into this request's trace, while preserving normal
// logging for code outside Analyze. Context isolation permits concurrent calls.
type logKey struct{}

var installLogs sync.Once

type traceHandler struct {
	fallback   slog.Handler
	transforms []func(slog.Handler) slog.Handler
}

func (h traceHandler) target(ctx context.Context) slog.Handler {
	if sink, ok := ctx.Value(logKey{}).(slog.Handler); ok {
		for _, f := range h.transforms {
			sink = f(sink)
		}
		return sink
	}
	return h.fallback
}
func (h traceHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.target(ctx).Enabled(ctx, l)
}
func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.target(ctx).Handle(ctx, r)
}
func (h traceHandler) WithAttrs(a []slog.Attr) slog.Handler {
	attrs := append([]slog.Attr(nil), a...)
	return traceHandler{h.fallback.WithAttrs(a), append(append([]func(slog.Handler) slog.Handler(nil), h.transforms...), func(s slog.Handler) slog.Handler { return s.WithAttrs(attrs) })}
}
func (h traceHandler) WithGroup(g string) slog.Handler {
	return traceHandler{h.fallback.WithGroup(g), append(append([]func(slog.Handler) slog.Handler(nil), h.transforms...), func(s slog.Handler) slog.Handler { return s.WithGroup(g) })}
}

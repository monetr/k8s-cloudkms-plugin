// Package glog is a drop-in replacement for the leveled logging API of
// github.com/golang/glog that writes one JSON object per line to stderr using
// log/slog. The root go.mod points github.com/golang/glog here, so upstream
// k8s-cloudkms-plugin code gets JSON logs without modification.
//
// Only the standard leveled functions are provided. If upstream starts using
// a glog function that isn't here, the build fails, so nothing goes missing
// silently.
//
// Flags: -v sets the verbosity for V(n) logs, as in glog. -logtostderr is
// accepted for compatibility and ignored; output always goes to stderr.
package glog

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// LevelFatal is the slog level used for Fatal and Exit messages.
const LevelFatal = slog.Level(12)

var (
	verbosity Level
	logger    = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == LevelFatal {
					return slog.String(slog.LevelKey, "FATAL")
				}
			}
			return a
		},
	}))
)

func init() {
	flag.Var(&verbosity, "v", "log level for V logs")
	flag.Bool("logtostderr", true, "ignored; logs always go to stderr as JSON")
}

// Level is the verbosity level for V logs. It implements flag.Value.
type Level int32

func (l *Level) get() Level { return Level(atomic.LoadInt32((*int32)(l))) }

// String implements flag.Value.
func (l *Level) String() string { return strconv.FormatInt(int64(l.get()), 10) }

// Get implements flag.Getter.
func (l *Level) Get() any { return l.get() }

// Set implements flag.Value.
func (l *Level) Set(value string) error {
	v, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return err
	}
	atomic.StoreInt32((*int32)(l), int32(v))
	return nil
}

// emit logs msg at level, attributing it to the caller `skip` frames above
// emit's caller.
func emit(level slog.Level, skip int, msg string, attrs ...slog.Attr) {
	ctx := context.Background()
	if !logger.Enabled(ctx, level) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(skip+2, pcs[:]) // skip runtime.Callers and emit
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.AddAttrs(attrs...)
	_ = logger.Handler().Handle(ctx, r)
}

func sprintln(args []any) string { return strings.TrimSuffix(fmt.Sprintln(args...), "\n") }

// Verbose is returned by V; logging through it only happens if the -v level
// is high enough. It is a bool so `if glog.V(2) { ... }` works as in glog.
type Verbose bool

// V reports whether verbosity at level is enabled.
func V(level Level) Verbose { return Verbose(verbosity.get() >= level) }

func (v Verbose) Info(args ...any) {
	if v {
		emit(slog.LevelInfo, 1, fmt.Sprint(args...), slog.Bool("verbose", true))
	}
}

func (v Verbose) Infoln(args ...any) {
	if v {
		emit(slog.LevelInfo, 1, sprintln(args), slog.Bool("verbose", true))
	}
}

func (v Verbose) Infof(format string, args ...any) {
	if v {
		emit(slog.LevelInfo, 1, fmt.Sprintf(format, args...), slog.Bool("verbose", true))
	}
}

func Info(args ...any)                    { emit(slog.LevelInfo, 1, fmt.Sprint(args...)) }
func Infoln(args ...any)                  { emit(slog.LevelInfo, 1, sprintln(args)) }
func Infof(format string, args ...any)    { emit(slog.LevelInfo, 1, fmt.Sprintf(format, args...)) }
func Warning(args ...any)                 { emit(slog.LevelWarn, 1, fmt.Sprint(args...)) }
func Warningln(args ...any)               { emit(slog.LevelWarn, 1, sprintln(args)) }
func Warningf(format string, args ...any) { emit(slog.LevelWarn, 1, fmt.Sprintf(format, args...)) }
func Error(args ...any)                   { emit(slog.LevelError, 1, fmt.Sprint(args...)) }
func Errorln(args ...any)                 { emit(slog.LevelError, 1, sprintln(args)) }
func Errorf(format string, args ...any)   { emit(slog.LevelError, 1, fmt.Sprintf(format, args...)) }

// Fatal logs, includes the stacks of all goroutines, and exits with status 2.
func Fatal(args ...any)                 { fatal(fmt.Sprint(args...)) }
func Fatalln(args ...any)               { fatal(sprintln(args)) }
func Fatalf(format string, args ...any) { fatal(fmt.Sprintf(format, args...)) }

func fatal(msg string) {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	emit(LevelFatal, 2, msg, slog.String("stack", string(buf)))
	os.Exit(2)
}

// Exit logs and exits with status 1, without a stack trace.
func Exit(args ...any)                 { emit(LevelFatal, 1, fmt.Sprint(args...)); os.Exit(1) }
func Exitln(args ...any)               { emit(LevelFatal, 1, sprintln(args)); os.Exit(1) }
func Exitf(format string, args ...any) { emit(LevelFatal, 1, fmt.Sprintf(format, args...)); os.Exit(1) }

// Flush is a no-op; every log line is written immediately.
func Flush() {}

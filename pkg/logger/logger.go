package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type Level int

const (
	LevelNone  Level = 0
	LevelError Level = 1
	LevelWarn  Level = 2
	LevelInfo  Level = 3
	LevelDebug Level = 4
)

var (
	current = LevelInfo
	mu      sync.Mutex
)

func SetLevel(l Level) { current = l }

func IsDebug() bool { return current >= LevelDebug }

func Printf(format string, args ...interface{}) {
	if current >= LevelInfo {
		write(os.Stdout, fmt.Sprintf(format, args...))
	}
}

func Debugf(format string, args ...interface{}) {
	if current >= LevelDebug {
		write(os.Stdout, fmt.Sprintf(format, args...))
	}
}

func Warn(msg string) {
	if current >= LevelWarn {
		printColour(msg, "\033[33m")
	}
}

func Warnf(format string, args ...interface{}) {
	if current >= LevelWarn {
		printColour(fmt.Sprintf(format, args...), "\033[33m")
	}
}

func Error(msg string) {
	if current >= LevelError {
		printColourTo(os.Stderr, msg, "\033[31m")
	}
}

func Errorf(format string, args ...interface{}) {
	if current >= LevelError {
		printColourTo(os.Stderr, fmt.Sprintf(format, args...), "\033[31m")
	}
}

func Success(msg string) {
	if current >= LevelInfo {
		printColour(msg, "\033[32m")
	}
}

func Successf(format string, args ...interface{}) {
	if current >= LevelInfo {
		printColour(fmt.Sprintf(format, args...), "\033[32m")
	}
}

func PrintResult(ok bool, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if ok {
		Success(msg)
	} else {
		Error(msg)
	}
}

func printColour(msg, code string) {
	printColourTo(os.Stdout, msg, code)
}

func printColourTo(f *os.File, msg, code string) {
	if isTerminal(f) {
		msg = code + msg + "\033[0m"
	}
	write(f, msg)
}

func write(w io.Writer, s string) {
	mu.Lock()
	defer mu.Unlock()
	_, _ = io.WriteString(w, s)
}

func isTerminal(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

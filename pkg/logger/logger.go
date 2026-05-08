package logger

import (
	"fmt"
	"os"
)

type Level int

const (
	LevelNone  Level = 0
	LevelError Level = 1
	LevelWarn  Level = 2
	LevelInfo  Level = 3
	LevelDebug Level = 4
)

var current = LevelInfo

func SetLevel(l Level) { current = l }

func IsDebug() bool { return current >= LevelDebug }

func Printf(format string, args ...interface{}) {
	if current >= LevelInfo {
		fmt.Fprintf(os.Stdout, format, args...)
	}
}

func Debugf(format string, args ...interface{}) {
	if current >= LevelDebug {
		fmt.Fprintf(os.Stdout, format, args...)
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
		printColour(msg, "\033[31m")
	}
}

func Errorf(format string, args ...interface{}) {
	if current >= LevelError {
		printColour(fmt.Sprintf(format, args...), "\033[31m")
	}
}

func Success(msg string) {
	printColour(msg, "\033[32m")
}

func Successf(format string, args ...interface{}) {
	printColour(fmt.Sprintf(format, args...), "\033[32m")
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
	fmt.Fprint(os.Stdout, code)
	fmt.Fprint(os.Stdout, msg)
	fmt.Fprint(os.Stdout, "\033[0m")
}

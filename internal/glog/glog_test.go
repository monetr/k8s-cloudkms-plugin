package glog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type entry struct {
	Level   string `json:"level"`
	Msg     string `json:"msg"`
	Verbose bool   `json:"verbose"`
	Stack   string `json:"stack"`
	Source  struct {
		Function string `json:"function"`
		File     string `json:"file"`
	} `json:"source"`
}

// capture redirects logging to a buffer for the duration of the test.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := logger
	logger = newLogger(&buf)
	t.Cleanup(func() { logger = prev })
	return &buf
}

func setVerbosity(t *testing.T, v string) {
	t.Helper()
	prev := verbosity.String()
	if err := flag.Set("v", v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { verbosity.Set(prev) })
}

func parse(t *testing.T, out []byte) []entry {
	t.Helper()
	var entries []entry
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var e entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestLevelsAndFormatting(t *testing.T) {
	buf := capture(t)

	Info("a", 1, "b")
	Infoln("a", 1, "b")
	Infof("x=%d", 1)
	Warning("w")
	Warningln("w", 2)
	Warningf("w=%d", 3)
	Error("e")
	Errorln("e", 2)
	Errorf("e=%d", 3)

	want := []entry{
		{Level: "INFO", Msg: "a1b"}, // fmt.Sprint only spaces between non-strings
		{Level: "INFO", Msg: "a 1 b"},
		{Level: "INFO", Msg: "x=1"},
		{Level: "WARN", Msg: "w"},
		{Level: "WARN", Msg: "w 2"},
		{Level: "WARN", Msg: "w=3"},
		{Level: "ERROR", Msg: "e"},
		{Level: "ERROR", Msg: "e 2"},
		{Level: "ERROR", Msg: "e=3"},
	}
	got := parse(t, buf.Bytes())
	if len(got) != len(want) {
		t.Fatalf("got %d log lines, want %d:\n%s", len(got), len(want), buf)
	}
	for i := range want {
		if got[i].Level != want[i].Level || got[i].Msg != want[i].Msg {
			t.Errorf("line %d: got %s %q, want %s %q", i, got[i].Level, got[i].Msg, want[i].Level, want[i].Msg)
		}
	}
}

func TestSourceIsCaller(t *testing.T) {
	buf := capture(t)
	setVerbosity(t, "1")

	Infof("plain")
	V(1).Infof("verbose")

	for _, e := range parse(t, buf.Bytes()) {
		if !strings.HasSuffix(e.Source.File, "glog_test.go") || !strings.HasSuffix(e.Source.Function, "TestSourceIsCaller") {
			t.Errorf("%q attributed to %s (%s), want the test", e.Msg, e.Source.Function, e.Source.File)
		}
	}
}

func TestVerbosity(t *testing.T) {
	buf := capture(t)
	setVerbosity(t, "2")

	V(1).Info("one")
	V(2).Infoln("two")
	V(3).Infof("three")
	if V(3) {
		t.Error("V(3) is true at -v=2")
	}
	if !V(2) {
		t.Error("V(2) is false at -v=2")
	}

	got := parse(t, buf.Bytes())
	if len(got) != 2 || got[0].Msg != "one" || got[1].Msg != "two" {
		t.Fatalf("unexpected verbose output:\n%s", buf)
	}
	for _, e := range got {
		if !e.Verbose || e.Level != "INFO" {
			t.Errorf("verbose entry %q: level=%s verbose=%v", e.Msg, e.Level, e.Verbose)
		}
	}

	setVerbosity(t, "0")
	buf.Reset()
	V(1).Info("hidden")
	if buf.Len() != 0 {
		t.Fatalf("V(1) logged at -v=0: %s", buf)
	}
}

func TestFlags(t *testing.T) {
	if err := flag.Set("v", "nope"); err == nil {
		t.Error("-v accepted a non-integer")
	}
	if err := flag.Set("logtostderr", "false"); err != nil {
		t.Errorf("-logtostderr should still be accepted: %v", err)
	}
}

// TestExiting re-runs the test binary to exercise functions that call os.Exit.
func TestExiting(t *testing.T) {
	if mode := os.Getenv("GLOG_TEST_EXIT"); mode != "" {
		switch mode {
		case "exit":
			Exitf("bye %d", 1)
		case "fatal":
			Fatalf("boom %d", 2)
		}
		return
	}

	for _, tc := range []struct {
		mode, msg string
		code      int
		stack     bool
	}{
		{mode: "exit", msg: "bye 1", code: 1, stack: false},
		{mode: "fatal", msg: "boom 2", code: 2, stack: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestExiting$")
			cmd.Env = append(os.Environ(), "GLOG_TEST_EXIT="+tc.mode)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()

			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.code {
				t.Fatalf("exit = %v, want code %d", err, tc.code)
			}
			got := parse(t, stderr.Bytes())
			if len(got) != 1 || got[0].Level != "FATAL" || got[0].Msg != tc.msg {
				t.Fatalf("unexpected output:\n%s", stderr.String())
			}
			if hasStack := strings.Contains(got[0].Stack, "goroutine"); hasStack != tc.stack {
				t.Fatalf("stack present = %v, want %v", hasStack, tc.stack)
			}
			if !strings.HasSuffix(got[0].Source.Function, "TestExiting") {
				t.Fatalf("attributed to %s, want the test", got[0].Source.Function)
			}
		})
	}
}

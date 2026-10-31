// A JSON-logging stand-in for github.com/golang/glog. The root go.mod replaces
// glog with this module, so upstream's code logs through log/slog unchanged.
module github.com/golang/glog

go 1.21

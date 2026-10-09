package bundle

import (
	"path/filepath"
	"testing"
)

func TestMatchAppID(t *testing.T) {
	cases := []struct {
		appID, bundleID string
		want            matchResult
	}{
		{"TEAM.com.example.app", "com.example.app", matchExact},
		{"TEAM.*", "com.example.app", matchWildcard},
		{"TEAM.com.example.*", "com.example.app.widget", matchWildcard},
		{"TEAM.com.example.*", "com.example", matchWildcard},
		{"TEAM.com.example.*", "com.examplefoo", matchNone},
		{"TEAM.com.other", "com.example.app", matchNone},
		{"", "com.example.app", matchNone},
	}
	for _, c := range cases {
		if got := matchAppID(c.appID, c.bundleID); got != c.want {
			t.Errorf("matchAppID(%q, %q) = %v, want %v", c.appID, c.bundleID, got, c.want)
		}
	}
}

func TestPayloadRoot(t *testing.T) {
	root := filepath.Join("tmp", "x")
	got, err := PayloadRoot(filepath.Join(root, "Payload", "App.app"))
	if err != nil || got != root {
		t.Errorf("PayloadRoot = %q, %v; want %q", got, err, root)
	}
	if _, err := PayloadRoot(filepath.Join(root, "App.app")); err == nil {
		t.Error("PayloadRoot accepted an app outside Payload/")
	}
}

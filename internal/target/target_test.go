package target

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSingleAndCIDR(t *testing.T) {
	got, err := Parse([]string{"10.0.0.5", "10.0.0.0/30"}, Options{Max: 100})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseDedupesAndSorts(t *testing.T) {
	got, err := Parse([]string{"10.0.0.10,10.0.0.9", "10.0.0.10"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.9", "10.0.0.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := "# lab\n192.0.2.1\n\n192.0.2.0/31 # pair\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Parse([]string{path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseAtFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(path, []byte("198.51.100.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Parse([]string{"@" + path}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("got %v", got)
	}
}

func TestParseExclude(t *testing.T) {
	got, err := Parse([]string{"10.0.0.0/30"}, Options{Exclude: []string{"10.0.0.1", "10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0", "10.0.0.3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTooMany(t *testing.T) {
	_, err := Parse([]string{"10.0.0.0/24"}, Options{Max: 10})
	if !errors.Is(err, ErrTooMany) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseHugeCIDR(t *testing.T) {
	if _, err := Parse([]string{"10.0.0.0/7"}, Options{}); err == nil {
		t.Fatal("expected refusal for a huge CIDR")
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse([]string{"not-an-ip"}, Options{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseIPv6(t *testing.T) {
	got, err := Parse([]string{"2001:db8::1"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "2001:db8::1" {
		t.Fatalf("got %v", got)
	}
}

func TestSplitSpecsKeepsPaths(t *testing.T) {
	if got := splitSpecs("/tmp/a,b.txt"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if got := splitSpecs("10.0.0.1,10.0.0.2"); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

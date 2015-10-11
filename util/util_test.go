package util

import "testing"

func TestReverse(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Hello, world", "dlrow ,olleH"},
		{"Hello, 世界", "界世 ,olleH"},
		{"", ""},
	}
	for _, c := range cases {
		got := Reverse_String(c.in)
		if got != c.want {
			t.Errorf("Reverse_String(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}

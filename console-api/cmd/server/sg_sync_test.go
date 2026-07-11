package main

import "testing"

func TestSGLabelPatch(t *testing.T) {
	const p = sgLabelPrefix
	cases := []struct {
		name    string
		current map[string]string
		want    map[string]bool
		expect  map[string]any // nil => no patch needed
	}{
		{
			name:    "already in sync -> no patch",
			current: map[string]string{p + "web": "", "kubevirt.io/domain": "vm1"},
			want:    map[string]bool{"web": true},
			expect:  nil,
		},
		{
			name:    "add missing labels",
			current: map[string]string{"kubevirt.io/domain": "vm1"},
			want:    map[string]bool{"web": true, "db": true},
			expect:  map[string]any{p + "web": "", p + "db": ""},
		},
		{
			name:    "remove stale label (the restart bug)",
			current: map[string]string{p + "cctest01-access": "", "kubevirt.io/domain": "vm1"},
			want:    map[string]bool{"windows-deploy": true},
			expect:  map[string]any{p + "windows-deploy": "", p + "cctest01-access": nil},
		},
		{
			name:    "empty desired removes all sg labels",
			current: map[string]string{p + "web": "", p + "db": ""},
			want:    map[string]bool{},
			expect:  map[string]any{p + "web": nil, p + "db": nil},
		},
		{
			name:    "never touches non-sg labels",
			current: map[string]string{"app.kubernetes.io/name": "vm1", p + "web": ""},
			want:    map[string]bool{"web": true},
			expect:  nil,
		},
	}
	for _, c := range cases {
		got := sgLabelPatch(c.current, c.want)
		if !patchEqual(got, c.expect) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.expect)
		}
	}
}

// patchEqual compares two merge-patch label maps, distinguishing a "" value
// (add/keep) from a nil value (delete).
func patchEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if (av == nil) != (bv == nil) {
			return false
		}
		if av != nil && av != bv {
			return false
		}
	}
	return true
}

package codesign

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestEncodeDERIntMatchesStdlib(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, -1, -128, -129, -256, -32768, 1 << 40, -(1 << 40)} {
		got := encodeDERSignedInt(v)
		want, _ := asn1.Marshal(v)
		if !bytes.Equal(got, want) {
			t.Errorf("encodeDERSignedInt(%d) = %x, want %x", v, got, want)
		}
	}
}

func TestEncodeDERDictKeysSorted(t *testing.T) {
	ent := map[string]interface{}{
		"keychain-access-groups": []interface{}{"T.*"},
		"application-identifier": "T.com.example",
		"get-task-allow":         true,
		"aps-environment":        "development",
	}
	first, err := encodeDER(ent)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _ := encodeDER(ent)
		if !bytes.Equal(first, again) {
			t.Fatal("DER encoding of a dictionary is not deterministic")
		}
	}
	order := []string{"application-identifier", "aps-environment", "get-task-allow", "keychain-access-groups"}
	last := -1
	for _, k := range order {
		idx := bytes.Index(first, []byte(k))
		if idx <= last {
			t.Fatalf("key %q out of order", k)
		}
		last = idx
	}
}

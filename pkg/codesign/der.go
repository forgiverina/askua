package codesign

import (
	"fmt"
	"sort"
)

func derLength(n uint64) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	nBytes := 0
	tmp := n
	for tmp > 0 {
		nBytes++
		tmp >>= 8
	}
	b := make([]byte, nBytes+1)
	b[0] = byte(0x80 | nBytes)
	for i := nBytes; i >= 1; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b
}

func encodeDER(v interface{}) ([]byte, error) {
	switch x := v.(type) {
	case bool:
		val := byte(0)
		if x {
			val = 1
		}
		return []byte{0x01, 0x01, val}, nil

	case uint64:
		return encodeDERInt(x), nil

	case int:
		return encodeDERSignedInt(int64(x)), nil

	case int64:
		return encodeDERSignedInt(x), nil

	case float32, float64:
		return nil, fmt.Errorf("float not supported in DER entitlements")

	case string:
		b := []byte(x)
		res := append([]byte{0x0c}, derLength(uint64(len(b)))...)
		return append(res, b...), nil

	case []interface{}:
		var inner []byte
		for _, item := range x {
			enc, err := encodeDER(item)
			if err != nil {
				return nil, err
			}
			inner = append(inner, enc...)
		}
		res := append([]byte{0x30}, derLength(uint64(len(inner)))...)
		return append(res, inner...), nil

	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		var inner []byte
		for _, key := range keys {
			val := x[key]
			valEnc, err := encodeDER(val)
			if err != nil {
				return nil, err
			}
			keyEnc := []byte(key)
			entry := append([]byte{0x0c}, derLength(uint64(len(keyEnc)))...)
			entry = append(entry, keyEnc...)
			entry = append(entry, valEnc...)
			seq := append([]byte{0x30}, derLength(uint64(len(entry)))...)
			seq = append(seq, entry...)
			inner = append(inner, seq...)
		}
		res := append([]byte{0x31}, derLength(uint64(len(inner)))...)
		return append(res, inner...), nil

	case nil:
		return []byte{0x05, 0x00}, nil // NULL

	default:
		return nil, fmt.Errorf("unsupported DER type %T", v)
	}
}

func encodeDERSignedInt(v int64) []byte {
	if v >= 0 {
		return encodeDERInt(uint64(v))
	}
	b := []byte{byte(v)}
	for v >>= 8; v != -1 || b[0]&0x80 == 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	res := append([]byte{0x02}, derLength(uint64(len(b)))...)
	return append(res, b...)
}

func encodeDERInt(v uint64) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	nBytes := 0
	tmp := v
	for tmp > 0 {
		nBytes++
		tmp >>= 8
	}
	b := make([]byte, nBytes)
	for i := nBytes - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	res := append([]byte{0x02}, derLength(uint64(len(b)))...)
	return append(res, b...)
}

package nuclei

import "fmt"

// payloadSet maps a payload name to its list of string values.
type payloadSet map[string][]string

// normalizePayloads converts the raw yaml payloads (inline lists) into a
// payloadSet. Wordlist-file payloads are not loaded here (gated).
func normalizePayloads(raw map[string]interface{}) payloadSet {
	ps := make(payloadSet)
	for k, v := range raw {
		switch t := v.(type) {
		case []interface{}:
			for _, item := range t {
				ps[k] = append(ps[k], fmt.Sprintf("%v", item))
			}
		case []string:
			ps[k] = append(ps[k], t...)
		}
	}
	return ps
}

// permutations generates the list of variable maps for the given attack mode.
//   - batteringram: same value used for all placeholders, iterate the union
//   - pitchfork: i-th value of each list together (parallel)
//   - clusterbomb: cartesian product
func permutations(attack string, ps payloadSet) []map[string]string {
	if len(ps) == 0 {
		return []map[string]string{{}}
	}
	keys := make([]string, 0, len(ps))
	for k := range ps {
		keys = append(keys, k)
	}

	switch attack {
	case "pitchfork":
		minLen := -1
		for _, k := range keys {
			if minLen < 0 || len(ps[k]) < minLen {
				minLen = len(ps[k])
			}
		}
		var out []map[string]string
		for i := 0; i < minLen; i++ {
			m := make(map[string]string)
			for _, k := range keys {
				m[k] = ps[k][i]
			}
			out = append(out, m)
		}
		return out

	case "clusterbomb":
		out := []map[string]string{{}}
		for _, k := range keys {
			var next []map[string]string
			for _, base := range out {
				for _, val := range ps[k] {
					m := make(map[string]string, len(base)+1)
					for bk, bv := range base {
						m[bk] = bv
					}
					m[k] = val
					next = append(next, m)
				}
			}
			out = next
		}
		return out

	default: // batteringram (single payload list shared)
		var out []map[string]string
		for _, k := range keys {
			for _, val := range ps[k] {
				m := make(map[string]string)
				// battering ram uses the same value for every placeholder
				for _, kk := range keys {
					m[kk] = val
				}
				out = append(out, m)
			}
			break // batteringram iterates one logical list
		}
		if len(out) == 0 {
			return []map[string]string{{}}
		}
		return out
	}
}

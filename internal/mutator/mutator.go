package mutator

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
)

// Payload representa um payload preparado para injeção
type Payload struct {
	Value    string
	Point    input.InjectionPoint
	Module   string // ex: "sqli", "xss", "ssti"
	Variant  string // ex: "error-based", "time-based", "double-encoded"
	Metadata map[string]string
}

// Mutate aplica mutações radamsa-style a um valor
func Mutate(value string, n int) []string {
	if n <= 0 {
		n = 50
	}
	var results []string
	for i := 0; i < n; i++ {
		results = append(results, applyMutation(value, rand.Intn(12)))
	}
	return results
}

func applyMutation(value string, strategy int) string {
	switch strategy {
	case 0: // Repeat block
		if len(value) > 2 {
			idx := rand.Intn(len(value) - 1)
			block := value[idx : idx+1+rand.Intn(min(5, len(value)-idx))]
			count := rand.Intn(50) + 2
			return value[:idx] + strings.Repeat(block, count) + value[idx:]
		}
	case 1: // Truncate
		if len(value) > 1 {
			return value[:rand.Intn(len(value))]
		}
	case 2: // Null byte injection
		idx := rand.Intn(len(value) + 1)
		return value[:idx] + "\x00" + value[idx:]
	case 3: // Bit flip
		if len(value) > 0 {
			bytes := []byte(value)
			idx := rand.Intn(len(bytes))
			bytes[idx] ^= byte(1 << uint(rand.Intn(8)))
			return string(bytes)
		}
	case 4: // Integer overflow
		overflows := []string{
			"2147483647", "2147483648", "-2147483648", "-2147483649",
			"9999999999999999999", "-1", "0", "-0",
			"9223372036854775807", "18446744073709551615",
			"1e308", "1e-308", "NaN", "Infinity", "-Infinity",
		}
		return overflows[rand.Intn(len(overflows))]
	case 5: // Unicode tricks
		tricks := []string{
			"\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e", // fullwidth <script>
			"\u0000", "\u200b", "\u200d", "\ufeff", "\u202e",
			"\uff0e\uff0e\uff0f", // fullwidth ../
			"ﬀ", "ﬁ", "ﬂ", "ﬃ", "ﬄ", // ligatures
			"\u0041\u030A", // A + combining ring = looks like Å
		}
		idx := rand.Intn(len(value) + 1)
		trick := tricks[rand.Intn(len(tricks))]
		return value[:idx] + trick + value[idx:]
	case 6: // Double encoding
		return doubleEncode(value)
	case 7: // Deep nesting
		depth := rand.Intn(50) + 10
		nested := value
		for i := 0; i < depth; i++ {
			nested = `{"x":` + nested + `}`
		}
		return nested
	case 8: // Format string
		formats := []string{"%s", "%x", "%n", "%d", "{{.}}", "${7*7}", "%00"}
		return value + formats[rand.Intn(len(formats))]
	case 9: // Long string
		return strings.Repeat(value, rand.Intn(1000)+100)
	case 10: // Special chars injection
		specials := []string{
			"'", "\"", "`", "\\", "\n", "\r", "\t",
			"<", ">", "&", "|", ";", "$", "(", ")",
			"{", "}", "[", "]", "\r\n", "\r\n\r\n",
		}
		s := specials[rand.Intn(len(specials))]
		idx := rand.Intn(len(value) + 1)
		return value[:idx] + s + value[idx:]
	case 11: // CRLF injection
		return value + "\r\nInjected-Header: true\r\n"
	}
	return value
}

// EncodeVariants gera variantes encodadas de um payload
func EncodeVariants(payload string) []string {
	variants := []string{payload}

	// URL encoded
	variants = append(variants, urlEncode(payload))
	// Double URL encoded
	variants = append(variants, urlEncode(urlEncode(payload)))
	// Unicode escaped
	variants = append(variants, unicodeEscape(payload))
	// HTML entities
	variants = append(variants, htmlEntities(payload))
	// Hex encoding
	variants = append(variants, hexEncode(payload))
	// Mixed case (para bypasses)
	variants = append(variants, mixCase(payload))

	return variants
}

func doubleEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		encoded := fmt.Sprintf("%%%02X", c)
		for _, ec := range encoded {
			result.WriteString(fmt.Sprintf("%%%02X", ec))
		}
	}
	return result.String()
}

func urlEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result.WriteRune(c)
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return result.String()
}

func unicodeEscape(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteString(fmt.Sprintf("\\u%04x", c))
	}
	return result.String()
}

func htmlEntities(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteString(fmt.Sprintf("&#x%x;", c))
	}
	return result.String()
}

func hexEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteString(fmt.Sprintf("0x%02x", c))
	}
	return result.String()
}

func mixCase(s string) string {
	var result strings.Builder
	for i, c := range s {
		if i%2 == 0 {
			result.WriteRune(c)
		} else {
			if c >= 'a' && c <= 'z' {
				result.WriteRune(c - 32)
			} else if c >= 'A' && c <= 'Z' {
				result.WriteRune(c + 32)
			} else {
				result.WriteRune(c)
			}
		}
	}
	return result.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

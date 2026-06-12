package mutator

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"unicode"
)

// SmartGen generates thousands of payloads based on the original value's data type and structure.
// This is the core differentiator from nuclei - we don't just replay known payloads,
// we generate massive volumes of structurally-aware mutations to discover unexpected behavior.
type SmartGen struct {
	MaxPayloads int
}

// Generate produces payloads tailored to the detected value type
func (sg *SmartGen) Generate(originalValue string, count int) []string {
	if count <= 0 {
		count = 1000
	}

	vtype := detectType(originalValue)
	var payloads []string

	switch vtype {
	case typeInteger:
		payloads = sg.intFuzz(originalValue, count)
	case typeFloat:
		payloads = sg.floatFuzz(originalValue, count)
	case typeString:
		payloads = sg.stringFuzz(originalValue, count)
	case typeEmail:
		payloads = sg.emailFuzz(originalValue, count)
	case typeURL:
		payloads = sg.urlFuzz(originalValue, count)
	case typeUUID:
		payloads = sg.uuidFuzz(originalValue, count)
	case typeJSON:
		payloads = sg.jsonFuzz(originalValue, count)
	case typeBoolean:
		payloads = sg.boolFuzz(count)
	case typePath:
		payloads = sg.pathFuzz(originalValue, count)
	default:
		payloads = sg.stringFuzz(originalValue, count)
	}

	// Always append type confusion payloads
	payloads = append(payloads, typeConfusion(originalValue)...)
	// Boundary payloads
	payloads = append(payloads, boundaryValues()...)

	return payloads
}

type valueType int

const (
	typeString valueType = iota
	typeInteger
	typeFloat
	typeEmail
	typeURL
	typeUUID
	typeJSON
	typeBoolean
	typePath
)

func detectType(val string) valueType {
	if val == "true" || val == "false" || val == "1" || val == "0" {
		if val == "true" || val == "false" {
			return typeBoolean
		}
	}
	if _, err := strconv.ParseInt(val, 10, 64); err == nil {
		return typeInteger
	}
	if _, err := strconv.ParseFloat(val, 64); err == nil {
		return typeFloat
	}
	if strings.Contains(val, "@") && strings.Contains(val, ".") {
		return typeEmail
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") || strings.HasPrefix(val, "//") {
		return typeURL
	}
	if len(val) == 36 && strings.Count(val, "-") == 4 {
		return typeUUID
	}
	if strings.HasPrefix(val, "{") || strings.HasPrefix(val, "[") {
		return typeJSON
	}
	if strings.Contains(val, "/") && !strings.Contains(val, " ") {
		return typePath
	}
	return typeString
}

func (sg *SmartGen) intFuzz(original string, count int) []string {
	base, _ := strconv.ParseInt(original, 10, 64)
	payloads := make([]string, 0, count)

	// Sequential neighbors
	for i := int64(-50); i <= 50; i++ {
		payloads = append(payloads, strconv.FormatInt(base+i, 10))
	}
	// Powers of 2 boundaries
	for _, v := range []int64{0, 1, -1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
		2147483647, 2147483648, -2147483648, -2147483649, 4294967295, 4294967296,
		9223372036854775807} {
		payloads = append(payloads, strconv.FormatInt(v, 10))
	}
	// Large random values
	for i := 0; i < count/4; i++ {
		payloads = append(payloads, strconv.FormatInt(rand.Int63(), 10))
		payloads = append(payloads, strconv.FormatInt(-rand.Int63(), 10))
	}
	// Type confusion: not an integer
	payloads = append(payloads, "NaN", "Infinity", "-Infinity", "null", "undefined",
		"true", "false", "[]", "{}", "1e999", "1e-999", "0x1", "0o7", "0b1",
		"1.1", "-0", "00", "01", "0x7fffffff", "0xffffffff",
		strings.Repeat("9", 100), strings.Repeat("1", 1000))
	// Arithmetic expressions
	payloads = append(payloads, "1+1", "1-1", "1*1", "1/0", "0/0")

	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) floatFuzz(original string, count int) []string {
	base, _ := strconv.ParseFloat(original, 64)
	payloads := make([]string, 0, count)

	// Neighborhood
	for i := -20; i <= 20; i++ {
		payloads = append(payloads, fmt.Sprintf("%.6f", base+float64(i)*0.1))
	}
	// Special IEEE 754 values
	specials := []string{"0.0", "-0.0", "1e308", "-1e308", "1e-308", "5e-324",
		"1.7976931348623157e+308", "2.2250738585072014e-308",
		"NaN", "Infinity", "-Infinity", "1e999", "-1e999",
		"0.1+0.2", "0.30000000000000004", "1.0000000000000002"}
	payloads = append(payloads, specials...)
	// Random floats
	for i := 0; i < count/3; i++ {
		payloads = append(payloads, fmt.Sprintf("%.15f", rand.Float64()*1e10-5e9))
	}
	// Many decimal places
	payloads = append(payloads, "0."+strings.Repeat("0", 100)+"1")
	payloads = append(payloads, strings.Repeat("9", 50)+"."+strings.Repeat("9", 50))

	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) stringFuzz(original string, count int) []string {
	payloads := make([]string, 0, count)
	n := len(original)

	// Length variations
	for _, mult := range []int{0, 1, 2, 5, 10, 50, 100, 500, 1000, 5000, 10000} {
		if mult == 0 {
			payloads = append(payloads, "")
		} else if n > 0 {
			payloads = append(payloads, strings.Repeat(original, mult))
		} else {
			payloads = append(payloads, strings.Repeat("A", mult))
		}
	}
	// Single char repeats at various lengths
	for _, c := range []string{"A", "a", "0", " ", "\t", "\n", "\x00", ".", "/", "\\", "'", "\"", "<", "{"} {
		for _, l := range []int{1, 10, 100, 1000, 5000} {
			payloads = append(payloads, strings.Repeat(c, l))
		}
	}
	// Truncations
	for i := 1; i < n && i < 20; i++ {
		payloads = append(payloads, original[:i])
	}
	// Case variations
	payloads = append(payloads, strings.ToUpper(original), strings.ToLower(original))
	// Unicode normalization attacks
	payloads = append(payloads, unicodePayloads(original)...)
	// Prefix/suffix injections
	prefixes := []string{"", " ", "\t", "\n", "\r\n", "\x00", "\ufeff", "\u200b"}
	suffixes := []string{"", " ", "\t", "\n", "\r\n", "\x00", "\ufeff"}
	for _, p := range prefixes {
		for _, s := range suffixes {
			if p != "" || s != "" {
				payloads = append(payloads, p+original+s)
			}
		}
	}
	// Radamsa-style mutations
	for i := 0; i < count/3; i++ {
		payloads = append(payloads, applyMutation(original, rand.Intn(12)))
	}
	// Format specifiers
	for _, f := range []string{"%s", "%d", "%x", "%n", "%p", "%%", "%99999s", "%s%s%s%s%s%s%s%s%s%s"} {
		payloads = append(payloads, f)
		payloads = append(payloads, original+f)
	}

	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) emailFuzz(original string, count int) []string {
	parts := strings.SplitN(original, "@", 2)
	local := "user"
	domain := "test.com"
	if len(parts) == 2 {
		local = parts[0]
		domain = parts[1]
	}

	payloads := make([]string, 0, count)
	// Malformed emails
	payloads = append(payloads,
		"", "@", "@@", local+"@", "@"+domain,
		local+"@"+domain+"."+strings.Repeat("a", 255),
		strings.Repeat("a", 255)+"@"+domain,
		local+"+tag@"+domain,
		local+"%00@"+domain,
		local+"@"+domain+"\n",
		`"'OR 1=1--"@`+domain,
		local+"@[127.0.0.1]",
		local+"@localhost",
		local+`"@`+domain,
		"<script>@"+domain,
		local+"@"+domain+"\r\nCC:victim@evil.com",
		local+"@"+strings.Repeat("a", 63)+".com",
		"."+local+"@"+domain,
		local+".@"+domain,
		local+"..test@"+domain,
	)
	// Generate random mutations of the email
	for i := 0; i < count-len(payloads); i++ {
		payloads = append(payloads, applyMutation(original, rand.Intn(12)))
	}

	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) urlFuzz(original string, count int) []string {
	payloads := make([]string, 0, count)

	payloads = append(payloads,
		"", "http://", "https://", "//", "///",
		"javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd", "gopher://127.0.0.1:6379/",
		"http://127.0.0.1", "http://localhost", "http://0.0.0.0",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/", "http://0x7f000001/",
		"http://evil.com@127.0.0.1/",
		"http://127.0.0.1#@evil.com",
		"http://"+strings.Repeat("a", 2000)+".com",
		original+"\r\nInjected: true",
		original+"%0d%0aInjected:true",
		"https://evil.com/"+strings.Repeat("../", 20)+"etc/passwd",
	)
	for i := 0; i < count-len(payloads); i++ {
		payloads = append(payloads, applyMutation(original, rand.Intn(12)))
	}
	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) uuidFuzz(original string, count int) []string {
	payloads := make([]string, 0, count)

	payloads = append(payloads,
		"", "00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"not-a-uuid", "1", "-1", "null", "undefined",
		original[:len(original)-1], original+"a",
		strings.ReplaceAll(original, "-", ""),
		strings.ToUpper(original),
		"../../../etc/passwd",
	)
	// Sequential UUIDs
	for i := 0; i < count/2; i++ {
		payloads = append(payloads, fmt.Sprintf("%08x-0000-0000-0000-%012x", rand.Int31(), rand.Int63()))
	}
	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) jsonFuzz(original string, count int) []string {
	payloads := make([]string, 0, count)

	payloads = append(payloads,
		"", "{}", "[]", "null", `{"__proto__":{"x":1}}`,
		`{"constructor":{"prototype":{"x":1}}}`,
		`[`+strings.Repeat(`{"a":1},`, 1000)+`{"a":1}]`,
		`{`+strings.Repeat(`"a":`, 100)+`1`+strings.Repeat(`}`, 100),
		`{"a":"`+strings.Repeat("A", 10000)+`"}`,
		`{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":`+strings.Repeat(`{}`, 1)+strings.Repeat(`}`, 10),
		`{"a":NaN}`, `{"a":Infinity}`, `{"a":undefined}`,
		`{"a":1,"a":2}`, // duplicate keys
		original+`,"injected":"true"`,
	)
	for i := 0; i < count-len(payloads); i++ {
		payloads = append(payloads, applyMutation(original, rand.Intn(12)))
	}
	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func (sg *SmartGen) boolFuzz(count int) []string {
	return []string{
		"true", "false", "True", "False", "TRUE", "FALSE",
		"1", "0", "-1", "2", "yes", "no", "on", "off",
		"null", "undefined", "NaN", "", "[]", "{}",
		"tRuE", "fAlSe", " true", "true ", "\ttrue",
	}
}

func (sg *SmartGen) pathFuzz(original string, count int) []string {
	payloads := make([]string, 0, count)

	// Traversal variations
	traversals := []string{
		"../", "..\\", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e/",
		"....//", "..../", "..%252f", "..%c0%af", "..%ef%bc%8f",
		"..\\/", "..;/",
	}
	for _, t := range traversals {
		for depth := 1; depth <= 10; depth++ {
			payloads = append(payloads, strings.Repeat(t, depth)+"etc/passwd")
			payloads = append(payloads, strings.Repeat(t, depth)+"windows/win.ini")
		}
	}
	// Null byte truncation
	payloads = append(payloads, original+"%00", original+"%00.png", original+"\x00")
	// Path normalization tricks
	payloads = append(payloads, "/./"+original, "//"+original, original+"/.", original+"/..")
	// Random mutations
	for i := 0; i < count-len(payloads); i++ {
		payloads = append(payloads, applyMutation(original, rand.Intn(12)))
	}
	if len(payloads) > count {
		payloads = payloads[:count]
	}
	return payloads
}

func unicodePayloads(original string) []string {
	var payloads []string
	// Homoglyphs
	homoglyphs := map[rune][]rune{
		'a': {'а', 'ɑ', 'α'}, 'e': {'е', 'ε'}, 'o': {'о', 'ο'},
		'p': {'р'}, 'c': {'с'}, 'i': {'і', 'ι'}, 'l': {'ⅼ', 'ⅰ'},
	}
	var result []rune
	for _, c := range original {
		if alts, ok := homoglyphs[unicode.ToLower(c)]; ok {
			result = append(result, alts[0])
		} else {
			result = append(result, c)
		}
	}
	payloads = append(payloads, string(result))
	// Right-to-left override
	payloads = append(payloads, "\u202e"+original)
	// Zero-width chars
	payloads = append(payloads, original[:len(original)/2]+"\u200b"+original[len(original)/2:])
	payloads = append(payloads, "\ufeff"+original)
	return payloads
}

func typeConfusion(original string) []string {
	return []string{
		"null", "undefined", "NaN", "Infinity", "-Infinity",
		"true", "false", "[]", "[null]", "{}", `{"x":1}`,
		"0", "-0", "0.0", "1e999", "",
		"[" + original + "]",
		`"` + original + `"`,
		`{"toString":{"source":"return 1"}}`,
	}
}

func boundaryValues() []string {
	return []string{
		"0", "1", "-1", "2", "-2",
		"127", "128", "-128", "-129",
		"255", "256", "-256",
		"32767", "32768", "-32768", "-32769",
		"65535", "65536",
		"2147483647", "2147483648", "-2147483648", "-2147483649",
		"4294967295", "4294967296",
		"9223372036854775807", "9223372036854775808",
		"18446744073709551615", "18446744073709551616",
		strings.Repeat("A", 256),
		strings.Repeat("A", 1024),
		strings.Repeat("A", 4096),
		strings.Repeat("A", 65536),
	}
}

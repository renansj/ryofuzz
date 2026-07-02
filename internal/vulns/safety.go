package vulns

import "sync/atomic"

// allowDestructive gates payloads that can damage the target (DROP/DELETE,
// stacked writes, xp_cmdshell, file/network exfiltration). Default is OFF:
// running ryofuzz against a genuinely vulnerable target must never delete a
// client's data or execute OS commands unless the operator opts in explicitly
// via --allow-destructive. See review finding F1.
var allowDestructive atomic.Bool

// SetAllowDestructive toggles the destructive-payload gate. Called once from
// the CLI layer after flag parsing, before any payload generation.
func SetAllowDestructive(v bool) { allowDestructive.Store(v) }

// AllowDestructive reports whether destructive payloads are permitted.
func AllowDestructive() bool { return allowDestructive.Load() }

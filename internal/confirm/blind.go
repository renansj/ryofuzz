package confirm

import (
	"math"
	"net/http"
	"strings"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/httpx"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// BlindConfirmer performs statistical confirmation of blind injection findings
type BlindConfirmer struct {
	Client  *http.Client
	Samples int
	Cfg     engine.Config
}

// NewBlindConfirmer creates a confirmer with defaults
func NewBlindConfirmer(cfg engine.Config) *BlindConfirmer {
	return &BlindConfirmer{
		Client: httpx.New(httpx.Options{
			TimeoutSec:         cfg.Timeout,
			Proxy:              cfg.Proxy,
			InsecureSkipVerify: !cfg.VerifyTLS,
		}),
		Samples: 5,
		Cfg:     cfg,
	}
}

// ConfirmTimeBased sends the payload multiple times and compares with a zero-delay variant
func (bc *BlindConfirmer) ConfirmTimeBased(cfg engine.Config, payload mutator.Payload, sleepSec int) (bool, float64) {
	sleepTimes := bc.measure(cfg, payload, bc.Samples)
	zeroPayload := zeroDelay(payload)
	zeroTimes := bc.measure(cfg, zeroPayload, bc.Samples)

	if len(sleepTimes) == 0 || len(zeroTimes) == 0 {
		return false, 0
	}

	meanSleep := mean(sleepTimes)
	meanZero := mean(zeroTimes)
	stdZero := stddev(zeroTimes)

	threshold := meanZero + 3*stdZero + float64(sleepSec*1000)*0.8
	delta := meanSleep - meanZero
	return meanSleep > threshold, delta
}

// ConfirmBoolean sends true and false payloads and compares body lengths
func (bc *BlindConfirmer) ConfirmBoolean(cfg engine.Config, truePayload, falsePayload mutator.Payload) bool {
	trueLens := bc.measureLens(cfg, truePayload, 3)
	falseLens := bc.measureLens(cfg, falsePayload, 3)

	if len(trueLens) < 3 || len(falseLens) < 3 {
		return false
	}

	// True responses must be consistent (stddev < 50)
	if stddev(toFloat(trueLens)) > 50 {
		return false
	}

	meanTrue := mean(toFloat(trueLens))
	meanFalse := mean(toFloat(falseLens))
	return math.Abs(meanTrue-meanFalse) > 50
}

func (bc *BlindConfirmer) measure(cfg engine.Config, payload mutator.Payload, n int) []float64 {
	var times []float64
	for i := 0; i < n; i++ {
		results := engine.Fuzz(cfg, nil, []mutator.Payload{payload}, 1, 0, 0, false)
		if len(results) > 0 && results[0].Error == nil {
			times = append(times, float64(results[0].Response.TimeMs))
		}
	}
	return times
}

func (bc *BlindConfirmer) measureLens(cfg engine.Config, payload mutator.Payload, n int) []int {
	var lens []int
	for i := 0; i < n; i++ {
		results := engine.Fuzz(cfg, nil, []mutator.Payload{payload}, 1, 0, 0, false)
		if len(results) > 0 && results[0].Error == nil {
			lens = append(lens, results[0].Response.BodyLength)
		}
	}
	return lens
}

func zeroDelay(p mutator.Payload) mutator.Payload {
	v := p.Value
	replacements := []struct{ old, new string }{
		{"SLEEP(5)", "SLEEP(0)"}, {"SLEEP(10)", "SLEEP(0)"},
		{"sleep(5)", "sleep(0)"}, {"sleep(10)", "sleep(0)"},
		{"pg_sleep(5)", "pg_sleep(0)"}, {"pg_sleep(10)", "pg_sleep(0)"},
		{"WAITFOR DELAY '0:0:5'", "WAITFOR DELAY '0:0:0'"},
		{"WAITFOR DELAY '0:0:10'", "WAITFOR DELAY '0:0:0'"},
	}
	for _, r := range replacements {
		v = strings.Replace(v, r.old, r.new, 1)
	}
	return mutator.Payload{Value: v, Point: p.Point, Module: p.Module, Variant: p.Variant}
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddev(vals []float64) float64 {
	if len(vals) < 2 {
		return 0
	}
	m := mean(vals)
	sum := 0.0
	for _, v := range vals {
		sum += (v - m) * (v - m)
	}
	return math.Sqrt(sum / float64(len(vals)))
}

func toFloat(ints []int) []float64 {
	f := make([]float64, len(ints))
	for i, v := range ints {
		f[i] = float64(v)
	}
	return f
}

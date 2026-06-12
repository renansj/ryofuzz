package reporter

import (
	"fmt"
	"html/template"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/renansj/ryofuzz/internal/vulns"
)

// ReportMeta metadata do relatório
type ReportMeta struct {
	Target        string
	StartTime     time.Time
	Duration      time.Duration
	TotalRequests int
	Version       string
}

type htmlData struct {
	Meta          ReportMeta
	Findings      []*vulns.Finding
	SevCounts     map[string]int
	ModuleCounts  map[string]int
	Total         int
	GeneratedAt   string
	PieSlices     []pieSlice
	BarItems      []barItem
	MaxBarCount   int
}

type pieSlice struct {
	Color      string
	StartX     float64
	StartY     float64
	EndX       float64
	EndY       float64
	LargeArc   int
	Label      string
	Count      int
	Percentage float64
}

type barItem struct {
	Label   string
	Count   int
	Color   string
	Width   float64
}

// ReportHTML gera relatório HTML self-contained
func ReportHTML(findings []*vulns.Finding, metadata ReportMeta, outputFile string) error {
	// Ordenar por severidade
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] < sevOrder[findings[j].Severity]
	})

	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	moduleCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[f.Severity]++
		moduleCounts[f.Module]++
	}

	total := len(findings)
	data := htmlData{
		Meta:         metadata,
		Findings:     findings,
		SevCounts:    sevCounts,
		ModuleCounts: moduleCounts,
		Total:        total,
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05"),
		PieSlices:    buildPieSlices(sevCounts, total),
		BarItems:     buildBarItems(moduleCounts),
	}
	if len(data.BarItems) > 0 {
		data.MaxBarCount = data.BarItems[0].Count
	}

	funcMap := template.FuncMap{
		"upper":    strings.ToUpper,
		"sevColor": sevColor,
		"add":      func(a, b int) int { return a + b },
		"mul":      func(a, b int) int { return a * b },
		"barWidth": func(count, max int) float64 {
			if max == 0 {
				return 0
			}
			return float64(count) / float64(max) * 100
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func sevColor(sev string) string {
	switch sev {
	case "critical":
		return "#ff4757"
	case "high":
		return "#ff6b35"
	case "medium":
		return "#ffa502"
	case "low":
		return "#3742fa"
	default:
		return "#00d2d3"
	}
}

func buildPieSlices(counts map[string]int, total int) []pieSlice {
	if total == 0 {
		return nil
	}
	order := []struct {
		key   string
		color string
	}{
		{"critical", "#ff4757"},
		{"high", "#ff6b35"},
		{"medium", "#ffa502"},
		{"low", "#3742fa"},
	}
	var slices []pieSlice
	cumAngle := 0.0
	for _, o := range order {
		c := counts[o.key]
		if c == 0 {
			continue
		}
		pct := float64(c) / float64(total)
		angle := pct * 2 * math.Pi
		startX := 100 + 80*math.Cos(cumAngle)
		startY := 100 + 80*math.Sin(cumAngle)
		cumAngle += angle
		endX := 100 + 80*math.Cos(cumAngle)
		endY := 100 + 80*math.Sin(cumAngle)
		largeArc := 0
		if angle > math.Pi {
			largeArc = 1
		}
		slices = append(slices, pieSlice{
			Color:      o.color,
			StartX:     startX,
			StartY:     startY,
			EndX:       endX,
			EndY:       endY,
			LargeArc:   largeArc,
			Label:      o.key,
			Count:      c,
			Percentage: pct * 100,
		})
	}
	return slices
}

func buildBarItems(moduleCounts map[string]int) []barItem {
	colors := []string{"#00d2d3", "#ff4757", "#ff6b35", "#ffa502", "#3742fa", "#a55eea", "#26de81", "#fd79a8"}
	var items []barItem
	for mod, count := range moduleCounts {
		items = append(items, barItem{Label: mod, Count: count})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	maxCount := 0
	if len(items) > 0 {
		maxCount = items[0].Count
	}
	for i := range items {
		items[i].Color = colors[i%len(colors)]
		if maxCount > 0 {
			items[i].Width = float64(items[i].Count) / float64(maxCount) * 100
		}
	}
	return items
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ryofuzz Report - {{.Meta.Target}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;padding:20px;line-height:1.6}
.container{max-width:1200px;margin:0 auto}
.header{background:#16213e;border-radius:12px;padding:30px;margin-bottom:20px;border:1px solid #0f3460}
.logo{font-size:28px;font-weight:bold;color:#00d2d3;font-family:monospace}
.logo span{color:#ff4757}
.meta{color:#888;margin-top:8px;font-size:14px}
.card{background:#16213e;border-radius:12px;padding:24px;margin-bottom:20px;border:1px solid #0f3460}
.card h2{color:#00d2d3;margin-bottom:16px;font-size:18px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.sev-box{padding:16px;border-radius:8px;text-align:center}
.sev-box .count{font-size:32px;font-weight:bold}
.sev-box .label{font-size:12px;text-transform:uppercase;opacity:0.8}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:768px){.charts{grid-template-columns:1fr}}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #0f3460}
th{color:#00d2d3;font-size:12px;text-transform:uppercase}
td{font-size:13px}
.payload-cell{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:12px}
.copy-btn{background:#0f3460;border:1px solid #00d2d3;color:#00d2d3;padding:2px 6px;border-radius:3px;cursor:pointer;font-size:10px;margin-left:4px}
.copy-btn:hover{background:#00d2d3;color:#1a1a2e}
details{margin-top:8px}
details summary{cursor:pointer;color:#00d2d3;font-size:12px}
details pre{background:#0f3460;padding:10px;border-radius:6px;overflow-x:auto;font-size:11px;margin-top:6px;max-height:300px;overflow-y:auto}
.footer{text-align:center;padding:20px;color:#555;font-size:12px;border-top:1px solid #0f3460;margin-top:20px}
.bar-row{display:flex;align-items:center;margin-bottom:8px}
.bar-label{width:120px;font-size:12px;text-align:right;padding-right:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;height:20px;background:#0f3460;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 0.3s}
.bar-count{width:40px;padding-left:8px;font-size:12px}
.legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px;justify-content:center}
.legend-item{display:flex;align-items:center;gap:4px;font-size:12px}
.legend-dot{width:10px;height:10px;border-radius:50%}
</style>
</head>
<body>
<div class="container">
<div class="header">
<div class="logo">ryo<span>fuzz</span> // Security Report</div>
<div class="meta">Target: <strong>{{.Meta.Target}}</strong> | Generated: {{.GeneratedAt}}</div>
</div>

<div class="card">
<h2>Executive Summary</h2>
<div class="summary-grid">
<div class="sev-box" style="background:rgba(255,71,87,0.15);border:1px solid #ff4757">
<div class="count" style="color:#ff4757">{{index .SevCounts "critical"}}</div>
<div class="label">Critical</div>
</div>
<div class="sev-box" style="background:rgba(255,107,53,0.15);border:1px solid #ff6b35">
<div class="count" style="color:#ff6b35">{{index .SevCounts "high"}}</div>
<div class="label">High</div>
</div>
<div class="sev-box" style="background:rgba(255,165,2,0.15);border:1px solid #ffa502">
<div class="count" style="color:#ffa502">{{index .SevCounts "medium"}}</div>
<div class="label">Medium</div>
</div>
<div class="sev-box" style="background:rgba(55,66,250,0.15);border:1px solid #3742fa">
<div class="count" style="color:#3742fa">{{index .SevCounts "low"}}</div>
<div class="label">Low</div>
</div>
</div>
</div>

<div class="charts">
<div class="card">
<h2>Severity Distribution</h2>
{{if .PieSlices}}
<svg viewBox="0 0 200 200" width="200" height="200" style="display:block;margin:0 auto">
{{range .PieSlices}}
<path d="M100,100 L{{printf "%.2f" .StartX}},{{printf "%.2f" .StartY}} A80,80 0 {{.LargeArc}},1 {{printf "%.2f" .EndX}},{{printf "%.2f" .EndY}} Z" fill="{{.Color}}"/>
{{end}}
</svg>
<div class="legend">
{{range .PieSlices}}
<div class="legend-item"><div class="legend-dot" style="background:{{.Color}}"></div>{{.Label}} ({{.Count}} - {{printf "%.0f" .Percentage}}%)</div>
{{end}}
</div>
{{else}}
<p style="text-align:center;color:#555">No findings</p>
{{end}}
</div>

<div class="card">
<h2>Findings by Module</h2>
{{range .BarItems}}
<div class="bar-row">
<div class="bar-label">{{.Label}}</div>
<div class="bar-track"><div class="bar-fill" style="width:{{printf "%.1f" .Width}}%;background:{{.Color}}"></div></div>
<div class="bar-count">{{.Count}}</div>
</div>
{{end}}
</div>
</div>

<div class="card">
<h2>Findings ({{.Total}})</h2>
<table>
<thead><tr><th>Sev</th><th>Title</th><th>Module</th><th>Injection Point</th><th>Payload</th><th>Evidence</th><th>Ref</th></tr></thead>
<tbody>
{{range $i, $f := .Findings}}
<tr>
<td><span class="badge" style="background:{{sevColor $f.Severity}}">{{upper $f.Severity}}</span></td>
<td>{{$f.Title}}</td>
<td>{{$f.Module}}</td>
<td>{{$f.Point.Name}} [{{$f.Point.Location}}]</td>
<td><span class="payload-cell" title="{{$f.Payload}}">{{$f.Payload}}</span><button class="copy-btn" onclick="navigator.clipboard.writeText(this.previousElementSibling.title)">copy</button></td>
<td>{{$f.Evidence}}</td>
<td>{{$f.OWASP}}<br/>{{$f.CWE}}</td>
</tr>
<tr><td colspan="7">
<details><summary>Request/Response Details</summary>
<pre>{{$f.Request}}</pre>
<pre>{{$f.Response}}</pre>
</details>
</td></tr>
{{end}}
</tbody>
</table>
</div>

<div class="footer">
ryofuzz v{{.Meta.Version}} | Duration: {{.Meta.Duration}} | Requests: {{.Meta.TotalRequests}} | Started: {{.Meta.StartTime.Format "2006-01-02 15:04:05"}}
</div>
</div>
</body>
</html>`

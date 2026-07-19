// Package report renders a Lumra verdict as a self-contained, shareable HTML
// evidence page — a single file with no external assets, styled to match
// lumra.crode.net. It exists so a diagnosis can be handed to a journalist,
// researcher, or the public as a standalone artifact of what was measured.
package report

import (
	"bytes"
	"html/template"
	"time"

	"github.com/croc100/lumra/internal/verdict"
)

// page is the data handed to the template.
type page struct {
	V         *verdict.Verdict
	Generated string
	Blocked   bool // any interference concluded (drives the accent color)
}

// HTML renders v into a self-contained HTML document.
func HTML(v *verdict.Verdict, generated time.Time) ([]byte, error) {
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, page{
		V:         v,
		Generated: generated.UTC().Format("2006-01-02 15:04:05 MST"),
		Blocked:   v.Type != verdict.OK && v.Type != verdict.Inconclusive,
	})
	return buf.Bytes(), err
}

var funcs = template.FuncMap{
	// mark maps an evidence outcome to its glyph.
	"mark": func(o verdict.Outcome) string {
		switch o {
		case verdict.Pass:
			return "✓"
		case verdict.Fail:
			return "✗"
		default:
			return "ⓘ"
		}
	},
	// cls maps an outcome to a CSS class.
	"cls": func(o verdict.Outcome) string {
		switch o {
		case verdict.Pass:
			return "pass"
		case verdict.Fail:
			return "fail"
		default:
			return "info"
		}
	},
	// attr renders the attribution axis, appending a self-identified authority.
	"attr": func(v *verdict.Verdict) string {
		if v.Attribution == "" {
			return ""
		}
		s := string(v.Attribution)
		if v.Authority != "" {
			s += " · " + v.Authority
		}
		return s
	},
	// nature renders the folded, user-facing character of the verdict.
	"nature": func(n verdict.Nature) string {
		switch n {
		case verdict.NatureControl:
			return "🚫 Blocked — access is being prevented"
		case verdict.NatureSurveillance:
			return "👁 Watched — the connection is being intercepted"
		case verdict.NatureDegradation:
			return "🐢 Slowed — this target is deliberately throttled"
		case verdict.NatureFault:
			return "⚠ Fault — a genuine outage, not interference"
		case verdict.NatureNone:
			return "✅ Clear — no interference detected"
		default:
			return "❔ Unclear — not enough signal"
		}
	},
}

var tmpl = template.Must(template.New("report").Funcs(funcs).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lumra report — {{.V.Target}}</title>
<style>
  :root{
    --bg:#0B0A0F; --panel:#131219; --line:#26252F; --line2:#2C2B38;
    --white:#F3F4F7; --sub:#C3C5CF; --mute:#898C99; --faint:#6C6F7C;
    --accent:#5E6AD2; --ok:#3fd07f; --fail:#e5654b; --warn:#d9a441;
    --mono:'JetBrains Mono',ui-monospace,'SF Mono',Menlo,monospace;
    --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--sub);font-family:var(--sans);line-height:1.6;
    -webkit-font-smoothing:antialiased;min-height:100vh;
    background-image:linear-gradient(rgba(245,245,243,.02) 1px,transparent 1px),
      linear-gradient(90deg,rgba(245,245,243,.02) 1px,transparent 1px);
    background-size:44px 44px;}
  .wrap{max-width:820px;margin:0 auto;padding:3.5rem 1.6rem 4rem}
  .eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.18em;text-transform:uppercase;
    color:var(--mute);display:flex;align-items:center;gap:.6rem;margin-bottom:1.4rem}
  .eyebrow::before{content:"";width:22px;height:1px;background:var(--line2)}
  .target{font-family:var(--mono);font-size:1.05rem;color:var(--white);word-break:break-all}
  .verdict{font-family:var(--sans);font-weight:800;letter-spacing:-.03em;line-height:1.05;
    font-size:clamp(2.4rem,7vw,3.8rem);color:var(--white);margin:.6rem 0 1.1rem}
  .verdict.blocked{color:var(--fail)}
  .verdict.ok{color:var(--ok)}
  .nature{font-family:var(--mono);font-size:.9rem;color:var(--sub);margin:-.4rem 0 .2rem}
  .meta{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:2rem}
  .pill{font-family:var(--mono);font-size:.74rem;letter-spacing:.04em;color:var(--sub);
    border:1px solid var(--line2);border-radius:999px;padding:.34rem .8rem}
  .pill b{color:var(--white);font-weight:500}
  .pill.conf-high{border-color:var(--fail);color:var(--fail)}
  .pill.conf-medium{border-color:var(--warn);color:var(--warn)}
  .cause{font-size:1.02rem;line-height:1.7;color:var(--sub);max-width:64ch;
    border-left:2px solid var(--accent);padding-left:1.1rem;margin-bottom:2.6rem}
  .sec{font-family:var(--mono);font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;
    color:var(--mute);margin-bottom:1rem}
  .ev{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--panel)}
  .row{display:flex;gap:.9rem;padding:.85rem 1.1rem;border-top:1px solid var(--line);
    font-family:var(--mono);font-size:.84rem;align-items:baseline}
  .row:first-child{border-top:0}
  .row .m{width:1.1em;flex:none;text-align:center}
  .row.pass .m{color:var(--ok)} .row.fail .m{color:var(--fail)} .row.info .m{color:var(--faint)}
  .row .probe{color:var(--mute);width:3.4em;flex:none}
  .row .detail{color:var(--sub)}
  .foot{margin-top:2.6rem;padding-top:1.4rem;border-top:1px solid var(--line);
    display:flex;flex-wrap:wrap;gap:.6rem 1.2rem;justify-content:space-between;
    font-family:var(--mono);font-size:.72rem;color:var(--faint)}
  .foot a{color:var(--mute);text-decoration:none}
  .foot a:hover{color:var(--white)}
</style>
</head>
<body>
  <div class="wrap">
    <p class="eyebrow">Lumra · Interference report</p>
    <p class="target">{{.V.Target}}</p>
    <h1 class="verdict {{if .Blocked}}blocked{{else if eq (printf "%s" .V.Type) "OK"}}ok{{end}}">{{.V.Type}}</h1>
    <p class="nature">{{nature .V.Nature}}</p>

    <div class="meta">
      <span class="pill conf-{{.V.Confidence}}">confidence <b>{{.V.Confidence}}</b></span>
      {{with attr .V}}<span class="pill">where <b>{{.}}</b></span>{{end}}
    </div>

    {{if .V.Cause}}<p class="cause">{{.V.Cause}}</p>{{end}}

    <p class="sec">Evidence — measured, not listed</p>
    <div class="ev">
      {{range .V.Evidence}}
      <div class="row {{cls .Outcome}}"><span class="m">{{mark .Outcome}}</span><span class="probe">{{.Probe}}</span><span class="detail">{{.Detail}}</span></div>
      {{end}}
    </div>

    <div class="foot">
      <span>Generated {{.Generated}} · self-produced measurement, no packet-content logging</span>
      <a href="https://lumra.crode.net">lumra.crode.net</a>
    </div>
  </div>
</body>
</html>
`))

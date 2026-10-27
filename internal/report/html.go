package report

import (
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// htmlPage is the single self-contained report page: no external CSS/JS, so
// it opens correctly from a USB stick or an email attachment. html/template
// (not text/template) is used throughout so every field pulled from scan
// data — hostnames, banners, share names, LDAP samples — is HTML-escaped
// automatically; none of it is trusted input.
const htmlPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>0800 report — {{.Doc.Finished.Format "2006-01-02 15:04"}}</title>
<style>
  :root { color-scheme: dark light; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem;
         background: #0e1420; color: #dce6f0; line-height: 1.5; }
  h1 { color: #7ee7d0; margin-bottom: .2rem; }
  .meta { color: #8aa; font-size: .9rem; margin-bottom: 1.5rem; }
  .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .stat { background: #182233; border-radius: .5rem; padding: .75rem 1rem; min-width: 7rem; }
  .stat b { display: block; font-size: 1.4rem; color: #7ee7d0; }
  .host { background: #141b2b; border-radius: .6rem; padding: 1.2rem 1.5rem; margin-bottom: 1rem;
          border-left: 4px solid var(--sev-color); }
  .host h2 { margin: 0 0 .4rem; font-size: 1.1rem; }
  .sev { display: inline-block; padding: .15rem .6rem; border-radius: 1rem; font-size: .75rem;
         font-weight: 600; text-transform: uppercase; color: #0e1420; background: var(--sev-color); }
  .sev-critical { --sev-color: #ff5d7a; }
  .sev-high     { --sev-color: #ff9d5c; }
  .sev-medium   { --sev-color: #ffd166; }
  .sev-low      { --sev-color: #9aa5c4; }
  .sev-info     { --sev-color: #5c7cff; }
  .kv { margin: .3rem 0; font-size: .92rem; color: #b8c4da; }
  .kv b { color: #dce6f0; }
  .findings { margin-top: .6rem; padding-left: 0; list-style: none; }
  .findings li { background: #0e1420; border-radius: .4rem; padding: .5rem .8rem; margin: .3rem 0; font-size: .88rem; }
  .ev { color: #7a8aa8; font-family: ui-monospace, Menlo, monospace; font-size: .8rem; display: block; margin-top: .2rem; }
  footer { color: #567; font-size: .8rem; margin-top: 2rem; }
  code { background: #0e1420; padding: .1rem .3rem; border-radius: .3rem; }
</style>
</head>
<body>
  <h1>0800 report</h1>
  <div class="meta">
    generated {{.Doc.Finished.Format "2006-01-02 15:04:05 MST"}} ·
    version {{.Doc.Version}} · scan took {{.Doc.Elapsed}}
  </div>

  <div class="stats">
    <div class="stat"><b>{{.Doc.Stats.Targets}}</b>targets</div>
    <div class="stat"><b>{{.Doc.Stats.Scanned}}</b>scanned</div>
    <div class="stat"><b>{{.Doc.Stats.OpenPorts}}</b>open ports</div>
    <div class="stat"><b>{{.Doc.Stats.Exposed}}</b>exposed hosts</div>
    <div class="stat"><b>{{.Doc.Stats.Findings}}</b>findings</div>
  </div>

  {{if not .Hosts}}
    <p>No host accepted an unauthenticated session on the probed ports.</p>
  {{end}}

  {{range .Hosts}}
  <div class="host sev-{{.Sev.String}}">
    <h2>{{.IP}}{{if and .Name (ne .Name .IP)}} — {{.Name}}{{end}}
      <span class="sev sev-{{.Sev.String}}">{{.Sev.String}}</span>
    </h2>
    {{if .Ports}}<div class="kv"><b>ports</b> {{joinPorts .Ports}}</div>{{end}}
    {{if .DC}}<div class="kv"><b>domain controller</b> yes</div>{{end}}
    {{if .SMB}}
      <div class="kv"><b>smb</b> dialect {{.SMB.Dialect}} · signing {{.SMB.Signing}}
        {{if .SMB.Auth}}· auth {{.SMB.Auth}}{{end}}
        {{if .SMB.Shares}}· shares {{range .SMB.Shares}}<code>{{.Name}}{{if .Writable}} (write){{end}}</code> {{end}}{{end}}
      </div>
    {{end}}
    {{if .NFS}}{{if .NFS.Exports}}
      <div class="kv"><b>nfs</b> {{range .NFS.Exports}}<code>{{.Path}}{{if .Mounted}} (mounted){{end}}</code> {{end}}</div>
    {{end}}{{end}}
    {{if .LDAP}}{{if or .LDAP.Bound .LDAP.DefaultDN}}
      <div class="kv"><b>ldap</b> anonymous bind {{.LDAP.Code}} · base {{.LDAP.DefaultDN}}
        {{if .LDAP.Entries}}· {{.LDAP.Entries}} object(s) readable{{end}}</div>
    {{end}}{{end}}
    {{if .FTP}}{{if .FTP.AnonOK}}
      <div class="kv"><b>ftp</b> anonymous login accepted · {{.FTP.Banner}}</div>
    {{end}}{{end}}
    {{range .DBs}}
      <div class="kv"><b>{{.Proto}}</b> {{.Status}}{{if .Version}} {{.Version}}{{end}}</div>
    {{end}}
    {{if .Findings}}
    <ul class="findings">
      {{range .Findings}}
      <li><b>{{.Label}}</b> — {{.Detail}} <span class="sev sev-{{.Severity.String}}">{{.Severity.String}}</span>
        {{range .Evidence}}<span class="ev">{{.}}</span>{{end}}
      </li>
      {{end}}
    </ul>
    {{end}}
  </div>
  {{end}}

  <footer>Only use 0800 against systems you own or have written permission to test.</footer>
</body>
</html>
`

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"joinPorts": joinPorts,
}).Parse(htmlPage))

type htmlData struct {
	Doc   Document
	Hosts []*scan.HostView
}

// WriteHTML renders a single, self-contained HTML report (no external
// assets) with the same content as WriteMarkdown, sorted the same way:
// highest severity and most-discovered first.
func WriteHTML(path string, doc Document) error {
	hosts := make([]*scan.HostView, 0, len(doc.Hosts))
	for _, h := range doc.Hosts {
		if h.Discovered() > 0 {
			hosts = append(hosts, h)
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Sev != hosts[j].Sev {
			return hosts[i].Sev > hosts[j].Sev
		}
		return hosts[i].Discovered() > hosts[j].Discovered()
	})

	var b strings.Builder
	if err := htmlTemplate.Execute(&b, htmlData{Doc: doc, Hosts: hosts}); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

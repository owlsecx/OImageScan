// ============================================================
//
//	OImageScan — Container Image / Layer Inspector
//	Author  : khaled.s.haddad
//	Website : owlsec.org
//	Language: Go (stdlib only, CGO disabled, static build) — OWL suite
//
//	Reads a "docker save" (or OCI) image tarball entirely with the
//	standard library: archive/tar for the outer archive and each
//	layer, compress/gzip for gzipped layers, encoding/json for
//	manifest.json and the image config. Reports the manifest and
//	config, per-layer sizes, a reconstructed build history, and a
//	content scan for risky files (setuid/setgid, world-writable,
//	secrets, SSH material, shell history). No Docker daemon needed.
//
// ============================================================
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
const (
	R   = "\033[91m"
	GRN = "\033[92m"
	YLW = "\033[93m"
	CY  = "\033[96m"
	W   = "\033[97m"
	B   = "\033[1m"
	X   = "\033[0m"
	MG  = "\033[95m"
	DIM = "\033[2m"
	OR  = "\033[38;5;208m"
	GY  = "\033[90m"
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear() {
	if !noColor {
		fmt.Print("\033[H\033[2J")
	}
}
func rule()            { fmt.Println(col(strings.Repeat("─", 66), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func header(title string) {
	fmt.Println()
	rule()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	rule()
	fmt.Println()
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	stdin.ReadString('\n')
}

func stripANSI(s string) string {
	out := []rune{}
	esc := false
	for _, r := range s {
		if r == '\033' {
			esc = true
			continue
		}
		if esc {
			if r == 'm' {
				esc = false
			}
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
func visw(s string) int { return len([]rune(stripANSI(s))) }
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), B+CY))
		if i < len(headers)-1 {
			hb.WriteString(col(" │ ", DIM))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("─", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "─┼─"), DIM))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" │ ", DIM))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

const BANNER = `
 ██████╗ ██╗███╗   ███╗ █████╗  ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔═══██╗██║████╗ ████║██╔══██╗██╔════╝ ██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║██╔████╔██║███████║██║  ███╗█████╗  ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
`

const (
	APPNAME = "OImageScan"
	SUITE   = "Owl Container Suite"
	TAGLINE = "Container Image / Layer Inspector"
	SUBLINE = "docker save / OCI tar · manifest · layers · build history · risky-file scan"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	rule()
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Core — docker save / OCI tar parsing (stdlib only)
// ---------------------------------------------------------------------------

type manifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Created      string `json:"created"`
	Config       struct {
		User         string              `json:"User"`
		Env          []string            `json:"Env"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		WorkingDir   string              `json:"WorkingDir"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		Labels       map[string]string   `json:"Labels"`
	} `json:"config"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

func readEntry(archivePath, name string) ([]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimPrefix(h.Name, "./") == strings.TrimPrefix(name, "./") {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("entry %q not found", name)
}

func loadManifest(p string) (*manifestEntry, error) {
	data, err := readEntry(p, "manifest.json")
	if err != nil {
		return nil, err
	}
	var m []manifestEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("empty manifest")
	}
	return &m[0], nil
}

func loadConfig(p string, m *manifestEntry) imageConfig {
	var cfg imageConfig
	if data, err := readEntry(p, m.Config); err == nil {
		json.Unmarshal(data, &cfg)
	}
	return cfg
}

func layerSizes(p string) map[string]int64 {
	sizes := map[string]int64{}
	f, err := os.Open(p)
	if err != nil {
		return sizes
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, e := tr.Next()
		if e != nil {
			break
		}
		sizes[strings.TrimPrefix(h.Name, "./")] = h.Size
	}
	return sizes
}

type risk struct{ layer, why, path string }

// scanRisks walks every layer's content and flags risky files.
func scanRisks(p string, m *manifestEntry) ([]risk, int, error) {
	layerSet := map[string]bool{}
	for _, l := range m.Layers {
		layerSet[strings.TrimPrefix(l, "./")] = true
	}
	var risks []risk
	entries := 0
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			break
		}
		name := strings.TrimPrefix(h.Name, "./")
		if !layerSet[name] {
			continue
		}
		br := bufio.NewReader(tr)
		var inner io.Reader = br
		if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
			if gz, gerr := gzip.NewReader(br); gerr == nil {
				inner = gz
			}
		}
		ltr := tar.NewReader(inner)
		for {
			lh, le := ltr.Next()
			if le == io.EOF {
				break
			}
			if le != nil {
				break
			}
			entries++
			pth := lh.Name
			mode := lh.FileInfo().Mode()
			if mode&os.ModeSetuid != 0 {
				risks = append(risks, risk{shortID(name), "SETUID binary", pth})
			}
			if mode&os.ModeSetgid != 0 {
				risks = append(risks, risk{shortID(name), "SETGID binary", pth})
			}
			if mode.Perm()&0o002 != 0 && !lh.FileInfo().IsDir() {
				risks = append(risks, risk{shortID(name), "world-writable", pth})
			}
			base := pth[strings.LastIndex(pth, "/")+1:]
			switch {
			case base == ".env" || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key"):
				risks = append(risks, risk{shortID(name), "secret/credential file", pth})
			case base == "id_rsa" || base == ".netrc" || base == ".npmrc" || base == ".dockercfg":
				risks = append(risks, risk{shortID(name), "credential file", pth})
			case strings.Contains(pth, "/.ssh/") && !lh.FileInfo().IsDir():
				risks = append(risks, risk{shortID(name), "ssh material", pth})
			case base == "bash_history" || base == ".bash_history":
				risks = append(risks, risk{shortID(name), "shell history leak", pth})
			}
		}
	}
	return risks, entries, nil
}

func shortID(s string) string {
	s = strings.TrimSuffix(s, "/layer.tar")
	s = strings.TrimPrefix(s, "blobs/sha256/")
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}

func humanSize(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------------------
// Renderers (shared by TUI + CLI)
// ---------------------------------------------------------------------------

func renderSummary(p string, m *manifestEntry, cfg imageConfig) {
	okMsg("Image manifest loaded")
	fmt.Println()
	table([]string{"Field", "Value"}, [][]string{
		{"Repo tags", orDash(strings.Join(m.RepoTags, ", "))},
		{"Config blob", m.Config},
		{"Layers", fmt.Sprintf("%d", len(m.Layers))},
		{"Architecture", orDash(cfg.Architecture)},
		{"OS", orDash(cfg.OS)},
		{"Created", orDash(cfg.Created)},
		{"User", orDash(cfg.Config.User)},
		{"WorkingDir", orDash(cfg.Config.WorkingDir)},
		{"Entrypoint", orDash(strings.Join(cfg.Config.Entrypoint, " "))},
		{"Cmd", orDash(strings.Join(cfg.Config.Cmd, " "))},
	})
	if cfg.Config.User == "" || cfg.Config.User == "root" || cfg.Config.User == "0" {
		fmt.Println()
		warnMsg("Image runs as ROOT (no USER set) — consider a non-root user.")
	}
}

func renderLayers(p string, m *manifestEntry) {
	sizes := layerSizes(p)
	info(fmt.Sprintf("%d layer(s)", len(m.Layers)))
	fmt.Println()
	rows := [][]string{}
	var total int64
	for i, l := range m.Layers {
		sz := sizes[strings.TrimPrefix(l, "./")]
		total += sz
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), shortID(l), humanSize(sz)})
	}
	table([]string{"#", "Layer", "Size"}, rows)
	fmt.Println()
	info("Total layer bytes: " + humanSize(total))
}

func renderHistory(cfg imageConfig) {
	info("Build history (Dockerfile reconstruction)")
	fmt.Println()
	if len(cfg.History) == 0 {
		warnMsg("no history recorded in the image config")
		return
	}
	for _, h := range cfg.History {
		cmd := h.CreatedBy
		cmd = strings.TrimPrefix(cmd, "/bin/sh -c #(nop) ")
		cmd = strings.TrimPrefix(cmd, "/bin/sh -c ")
		cmd = strings.TrimSpace(cmd)
		if len(cmd) > 100 {
			cmd = cmd[:100] + "..."
		}
		fmt.Println("  " + col("▸", CY) + " " + col(cmd, W))
		low := strings.ToLower(cmd)
		if strings.Contains(low, "password") || strings.Contains(low, "secret") || strings.Contains(low, "token") || strings.Contains(low, "api_key") {
			warnMsg("    ^ possible secret in build layer")
		}
	}
}

func renderRisks(risks []risk, entries, nlayers int) {
	info(fmt.Sprintf("Scanned %d file entries across %d layer(s)", entries, nlayers))
	fmt.Println()
	if len(risks) == 0 {
		okMsg("No risky files detected.")
		return
	}
	sort.Slice(risks, func(i, j int) bool { return risks[i].why < risks[j].why })
	rows := [][]string{}
	for _, r := range risks {
		if len(rows) >= 300 {
			break
		}
		rows = append(rows, []string{r.layer, r.why, r.path})
	}
	table([]string{"Layer", "Risk", "Path"}, rows)
	fmt.Println()
	warnMsg(fmt.Sprintf("%d risky file(s) flagged.", len(risks)))
}

// ---------------------------------------------------------------------------
// Interactive handlers
// ---------------------------------------------------------------------------

var imgPath string

func askImage() bool {
	if imgPath != "" {
		if _, err := os.Stat(imgPath); err == nil {
			return true
		}
	}
	p := strings.TrimSpace(prompt("path to image tar (docker save -o img.tar ...)"))
	if p == "" {
		return false
	}
	if _, err := os.Stat(p); err != nil {
		errMsg(err.Error())
		return false
	}
	imgPath = p
	return true
}

func withImage(render func(m *manifestEntry, cfg imageConfig)) {
	clear()
	banner()
	if !askImage() {
		pause()
		return
	}
	m, err := loadManifest(imgPath)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	cfg := loadConfig(imgPath, m)
	clear()
	banner()
	render(m, cfg)
	pause()
}

func doSummary() {
	withImage(func(m *manifestEntry, cfg imageConfig) { header("Image Summary"); renderSummary(imgPath, m, cfg) })
}
func doLayers() {
	withImage(func(m *manifestEntry, cfg imageConfig) { header("Layers"); renderLayers(imgPath, m) })
}
func doHistory() {
	withImage(func(m *manifestEntry, cfg imageConfig) { header("Build History"); renderHistory(cfg) })
}
func doScan() {
	withImage(func(m *manifestEntry, cfg imageConfig) {
		header("Risky-File Scan")
		risks, entries, err := scanRisks(imgPath, m)
		if err != nil {
			errMsg(err.Error())
			return
		}
		renderRisks(risks, entries, len(m.Layers))
	})
}

// ---------------------------------------------------------------------------
// Interactive menu
// ---------------------------------------------------------------------------

func menu(title string, items [][2]string) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for i, it := range items {
		fmt.Println("  " + col(pad(fmt.Sprintf("[%d]", i+1), 4), CY+B) + "  " +
			col(pad(it[0], 24), W) + col("─ "+it[1], DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 24), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R+B) + "  " + col(pad("Exit", 24), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	rule()
	return prompt("Select option")
}

func interactive() {
	for {
		c := menu("Main Menu", [][2]string{
			{"Image summary", "manifest + config, root-user check"},
			{"List layers", "layer digests with sizes"},
			{"Build history", "Dockerfile reconstruction + secrets"},
			{"Risky-file scan", "setuid / world-writable / secrets / ssh"},
		})
		switch strings.ToLower(c) {
		case "1":
			doSummary()
		case "2":
			doLayers()
		case "3":
			doHistory()
		case "4":
			doScan()
		case "h", "help", "?":
			tuiHelp()
		case "0", "00", "q", "exit", "":
			clear()
			okMsg("Goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	sec := func(t string) { fmt.Println("  " + col(t, CY+B)) }
	sec("USAGE")
	fmt.Println("    " + APPNAME + " [flags]            (no flags → interactive TUI)")
	fmt.Println()
	sec("DESCRIPTION")
	fmt.Println("    Inspect a 'docker save' / OCI image tarball offline: manifest + config,")
	fmt.Println("    per-layer sizes, reconstructed build history, and a risky-file content scan.")
	fmt.Println("    No Docker daemon required — it reads the tar directly.")
	fmt.Println()
	sec("INPUT")
	fmt.Println("    --input FILE      image tarball (docker save -o img.tar IMAGE)")
	fmt.Println("    --pcap FILE       alias for --input")
	fmt.Println()
	sec("SECTIONS (default: all)")
	fmt.Println("    --summary         manifest + config only")
	fmt.Println("    --layers          layer sizes only")
	fmt.Println("    --history         build history only")
	fmt.Println("    --scan            risky-file scan only")
	fmt.Println()
	sec("GENERAL")
	fmt.Println("    --no-color  --demo  --selftest  --version  -h/--help")
	fmt.Println()
	sec("EXAMPLES")
	fmt.Println("    docker save -o nginx.tar nginx:latest && " + APPNAME + " --input nginx.tar")
	fmt.Println("    " + APPNAME + " --input app.tar --scan")
	fmt.Println("    " + APPNAME + " --input app.tar --summary --history")
	fmt.Println("    " + APPNAME + " --demo")
	fmt.Println()
	rule()
}

func analyzeAll(p string, summary, layers, history, scan bool) int {
	m, err := loadManifest(p)
	if err != nil {
		errMsg(err.Error())
		return 1
	}
	cfg := loadConfig(p, m)
	if summary {
		header("Image Summary")
		renderSummary(p, m, cfg)
	}
	if layers {
		header("Layers")
		renderLayers(p, m)
	}
	if history {
		header("Build History")
		renderHistory(cfg)
	}
	if scan {
		header("Risky-File Scan")
		risks, entries, err := scanRisks(p, m)
		if err != nil {
			errMsg(err.Error())
			return 1
		}
		renderRisks(risks, entries, len(m.Layers))
	}
	return 0
}

func main() {
	var (
		fIn    = flag.String("input", "", "")
		fPcap  = flag.String("pcap", "", "")
		fSum   = flag.Bool("summary", false, "")
		fLay   = flag.Bool("layers", false, "")
		fHis   = flag.Bool("history", false, "")
		fScan  = flag.Bool("scan", false, "")
		fNoCol = flag.Bool("no-color", false, "")
		fDemo  = flag.Bool("demo", false, "")
		fSelf  = flag.Bool("selftest", false, "")
		fVer   = flag.Bool("version", false, "")
	)
	flag.Usage = usage
	flag.Parse()
	if *fNoCol {
		noColor = true
	}
	in := *fIn
	if in == "" {
		in = *fPcap
	}
	switch {
	case *fVer:
		fmt.Printf("%s %s  (OWL suite — %s / %s)\n", APPNAME, VERSION, AUTHOR, WEBSITE)
		return
	case *fSelf:
		os.Exit(runSelfTest())
	case *fDemo:
		path, cleanup, err := writeDemoImage()
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		defer cleanup()
		banner()
		info("synthetic docker-save image: " + path)
		os.Exit(analyzeAll(path, true, true, true, true))
	case in != "":
		// default: all sections unless a specific one is requested
		any := *fSum || *fLay || *fHis || *fScan
		banner()
		if any {
			os.Exit(analyzeAll(in, *fSum, *fLay, *fHis, *fScan))
		}
		os.Exit(analyzeAll(in, true, true, true, true))
	default:
		interactive()
	}
}

// ---------------------------------------------------------------------------
// Synthetic docker-save image builder (demo + self-test)
// ---------------------------------------------------------------------------

// buildDemoImage assembles a valid docker-save tarball in memory containing a
// config with history and one gzipped layer holding several risky files.
func buildDemoImage() []byte {
	// Inner layer tar (then gzipped).
	var layerBuf bytes.Buffer
	ltw := tar.NewWriter(&layerBuf)
	add := func(name string, mode int64, body string) {
		ltw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg})
		ltw.Write([]byte(body))
	}
	add("app/main", 0o755, "ELF-ish binary")
	add("usr/bin/ping", 0o4755, "setuid binary") // setuid
	add("app/.env", 0o644, "API_KEY=supersecret\n")
	add("root/.ssh/id_rsa", 0o600, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	add("tmp/scratch", 0o666, "world writable") // world-writable
	add("root/.bash_history", 0o600, "curl http://x | sh\n")
	ltw.Close()
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write(layerBuf.Bytes())
	gw.Close()

	cfg := map[string]any{
		"architecture": "amd64",
		"os":           "linux",
		"created":      "2026-01-01T00:00:00Z",
		"config": map[string]any{
			"User":       "",
			"Cmd":        []string{"/bin/sh"},
			"WorkingDir": "/app",
		},
		"history": []map[string]any{
			{"created_by": "/bin/sh -c #(nop) ADD file:... in /"},
			{"created_by": "/bin/sh -c #(nop) ENV API_KEY=supersecret"},
			{"created_by": "/bin/sh -c apt-get update && apt-get install -y curl"},
		},
	}
	cfgJSON, _ := json.Marshal(cfg)
	sum := sha256.Sum256(cfgJSON)
	cfgName := hex.EncodeToString(sum[:]) + ".json"

	manifest := []map[string]any{{
		"Config":   cfgName,
		"RepoTags": []string{"demo/owl:latest"},
		"Layers":   []string{"layer0.tar"},
	}}
	manJSON, _ := json.Marshal(manifest)

	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	writeFile := func(name string, body []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	writeFile(cfgName, cfgJSON)
	writeFile("layer0.tar", gz.Bytes())
	writeFile("manifest.json", manJSON)
	tw.Close()
	return out.Bytes()
}

func writeDemoImage() (string, func(), error) {
	f, err := os.CreateTemp("", "oimagescan-demo-*.tar")
	if err != nil {
		return "", func() {}, err
	}
	f.Write(buildDemoImage())
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

func runSelfTest() int {
	banner()
	header("Self-Test")
	pass, fail := 0, 0
	ck := func(name string, cond bool, detail string) {
		if cond {
			pass++
			fmt.Println("  " + col("[✔] ", GRN) + col(name, W))
		} else {
			fail++
			fmt.Println("  " + col("[✘] ", R) + col(name, W) + col("  "+detail, GY))
		}
	}
	path, cleanup, err := writeDemoImage()
	if err != nil {
		errMsg(err.Error())
		return 1
	}
	defer cleanup()

	m, err := loadManifest(path)
	ck("manifest.json parses", err == nil && m != nil, fmt.Sprint(err))
	if m == nil {
		errMsg("cannot continue without manifest")
		return 1
	}
	ck("one layer referenced", len(m.Layers) == 1, fmt.Sprint(m.Layers))
	ck("repo tag present", len(m.RepoTags) == 1 && m.RepoTags[0] == "demo/owl:latest", fmt.Sprint(m.RepoTags))

	cfg := loadConfig(path, m)
	ck("config: architecture amd64", cfg.Architecture == "amd64", cfg.Architecture)
	ck("config: runs as root (empty User)", cfg.Config.User == "", cfg.Config.User)
	ck("config: history has 3 steps", len(cfg.History) == 3, fmt.Sprint(len(cfg.History)))

	sizes := layerSizes(path)
	ck("layer size resolved", sizes["layer0.tar"] > 0, fmt.Sprint(sizes))

	risks, entries, err := scanRisks(path, m)
	ck("scan walked gzipped layer entries", err == nil && entries >= 6, fmt.Sprint(entries, err))
	has := func(why string) bool {
		for _, r := range risks {
			if r.why == why {
				return true
			}
		}
		return false
	}
	ck("detects SETUID binary", has("SETUID binary"), "")
	ck("detects world-writable file", has("world-writable"), "")
	ck("detects secret/credential file (.env)", has("secret/credential file"), "")
	ck("detects credential file (id_rsa)", has("credential file") || has("ssh material"), "")
	ck("detects shell history leak", has("shell history leak"), "")

	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
		return 0
	}
	errMsg(fmt.Sprintf("%d passed, %d FAILED", pass, fail))
	return 1
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OImageScan inspects a container image saved as a tarball (docker save -o img.tar IMAGE, or an OCI layout) without a Docker daemon. It reads the manifest and config, lists the layers with their sizes, reconstructs the build history (an approximate Dockerfile), and scans the contents of every layer for risky files.",
	"The risky-file scan flags setuid/setgid binaries, world-writable files, secret and credential files (.env, *.pem, *.key, id_rsa, .netrc, .npmrc, .dockercfg), SSH material and leaked shell history. Everything is read with the Go standard library (tar + gzip + json).",
}

var owlHelpFlow = []string{
	"First export an image to a tar:  docker save -o app.tar your/image:tag . Then type an option number; the first one asks for the tar path and the rest reuse it. [H] opens this help, [0] or q quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Image summary: repo tags, config blob, layer count, architecture, OS, user, working dir, entrypoint and command. Warns if the image runs as root."},
	{"2", "List layers: each layer's (shortened) digest and size, plus the total."},
	{"3", "Build history: the reconstructed build steps from the image config, flagging any step whose command contains a password/secret/token/api_key."},
	{"4", "Risky-file scan: walks the files inside every layer and flags setuid/setgid binaries, world-writable files, secrets, SSH keys and shell history."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "A secret added in an early layer stays in the image even if a later layer deletes it. The content scan sees it; the running container may not show it."},
	{"*", "Running as root is the most common finding. Add a USER line to your Dockerfile and rebuild."},
	{"*", "On the CLI, --input runs all four sections at once; add --scan (or --summary/--layers/--history) to limit the output. Try --demo to see a full report on a synthetic image."},
}

func owlHelpCLI() { usage() }

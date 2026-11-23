package scan

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type request struct {
	Host       string `json:"host"`
	Ports      []int  `json:"ports"`
	TimeoutMS  int    `json:"timeoutMs"`
	Authorized bool   `json:"authorized"`
}

type result struct {
	Port      int     `json:"port"`
	Service   string  `json:"service"`
	Status    string  `json:"status"`
	Risk      string  `json:"risk"`
	ConnectMS float64 `json:"connectMs"`
	Banner    string  `json:"banner,omitempty"`
	Note      string  `json:"note"`
}

var services = map[int]string{
	22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 3000: "Development", 3306: "MySQL", 5432: "PostgreSQL",
	5173: "Vite Dev", 6379: "Redis", 8000: "Development", 8080: "HTTP Proxy",
	8443: "HTTPS Alt", 27017: "MongoDB",
}
var risky = map[int]bool{3306: true, 5432: true, 6379: true, 27017: true}
var dev = map[int]bool{3000: true, 5173: true, 8000: true, 8080: true}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var in request
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	in.Host = strings.TrimSpace(strings.TrimSuffix(in.Host, "."))
	if !in.Authorized {
		http.Error(w, `{"error":"confirm that you own or are authorized to test this host"}`, http.StatusForbidden)
		return
	}
	if in.Host == "" || len(in.Host) > 253 || strings.ContainsAny(in.Host, "/\\:@ ") {
		http.Error(w, `{"error":"enter a valid hostname or public IP address"}`, http.StatusBadRequest)
		return
	}
	if len(in.Ports) == 0 || len(in.Ports) > 32 {
		http.Error(w, `{"error":"select between 1 and 32 ports"}`, http.StatusBadRequest)
		return
	}
	seen := map[int]bool{}
	for _, port := range in.Ports {
		if port < 1 || port > 65535 || seen[port] {
			http.Error(w, `{"error":"ports must be unique values from 1 to 65535"}`, http.StatusBadRequest)
			return
		}
		seen[port] = true
	}
	if in.TimeoutMS < 250 {
		in.TimeoutMS = 1000
	}
	if in.TimeoutMS > 3000 {
		in.TimeoutMS = 3000
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, in.Host)
	if err != nil || len(ips) == 0 {
		http.Error(w, `{"error":"host could not be resolved"}`, http.StatusBadRequest)
		return
	}
	// Only globally routable addresses are eligible. This blocks private-network,
	// loopback, link-local, and cloud metadata targets from the hosted scanner.
	for _, ip := range ips {
		if !ip.IP.IsGlobalUnicast() || ip.IP.IsPrivate() || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() {
			http.Error(w, `{"error":"private, local and link-local targets are not permitted by the hosted scanner"}`, http.StatusForbidden)
			return
		}
	}
	targetIP := ips[0].IP.String()
	out := make([]result, len(in.Ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, port := range in.Ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = check(ctx, targetIP, port, time.Duration(in.TimeoutMS)*time.Millisecond)
		}(i, port)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })

	counts := map[string]int{"OPEN": 0, "CLOSED": 0, "TIMEOUT": 0}
	var total float64
	min, max := 0.0, 0.0
	alerts := 0
	for _, item := range out {
		counts[item.Status]++
		if item.Status == "OPEN" && item.Risk == "EXPOSED_DATA_PORT" {
			alerts++
		}
		total += item.ConnectMS
		if min == 0 || item.ConnectMS < min {
			min = item.ConnectMS
		}
		if item.ConnectMS > max {
			max = item.ConnectMS
		}
	}
	avg := 0.0
	if len(out) > 0 {
		avg = total / float64(len(out))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"host": in.Host, "resolvedIP": targetIP, "results": out, "counts": counts,
		"riskAlerts": alerts, "latency": map[string]float64{"minMs": min, "avgMs": avg, "maxMs": max},
		"scannedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func check(ctx context.Context, host string, port int, timeout time.Duration) result {
	start := time.Now()
	item := result{
		Port: port, Service: services[port], Status: "CLOSED", Risk: "SAFE_PUBLIC",
		Note: "No unexpected exposure detected.",
	}
	if item.Service == "" {
		item.Service = "Unknown service"
	}
	if risky[port] {
		item.Risk = "EXPOSED_DATA_PORT"
		item.Note = "Data service detected: restrict to trusted networks and enforce authentication."
	} else if dev[port] {
		item.Risk = "DEV_INTERNAL"
		item.Note = "Development or app port: keep behind an authenticated gateway or private network."
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	item.ConnectMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			item.Status = "TIMEOUT"
			item.Risk = "UNREACHABLE"
		}
		return item
	}
	defer conn.Close()
	item.Status = "OPEN"
	if item.Risk == "SAFE_PUBLIC" {
		item.Note = "Reachable. Confirm the service is intended to be public and protected with TLS where appropriate."
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		banner := strings.Map(func(char rune) rune {
			if char >= 32 && char <= 126 {
				return char
			}
			if char == '\t' {
				return ' '
			}
			return -1
		}, string(buf[:n]))
		item.Banner = strings.TrimSpace(banner)
		if len(item.Banner) > 120 {
			item.Banner = item.Banner[:120]
		}
	}
	return item
}

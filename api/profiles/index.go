package profiles

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

type Profile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Host        string   `json:"host"`
	Ports       []int    `json:"ports"`
	TimeoutMS   int      `json:"timeoutMs"`
	Description string   `json:"description"`
}

var (
	mu sync.RWMutex
	custom = []Profile{}
	seeds = []Profile{
		{ID:"web-tls", Name:"Web & TLS Edge", Host:"example.com", Ports:[]int{80,443,8443}, TimeoutMS:1200, Description:"Standard web and encrypted web entry points."},
		{ID:"data", Name:"Database & Cache Check", Host:"example.com", Ports:[]int{5432,6379,3306,27017}, TimeoutMS:1000, Description:"Sensitive data services. These should not be exposed publicly without a deliberate access-control design."},
		{ID:"dev", Name:"Dev & App Ports", Host:"example.com", Ports:[]int{3000,5173,8000,8080}, TimeoutMS:1000, Description:"Development servers and application consoles that are commonly intended for private networks."},
	}
)

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		mu.RLock()
		all := append(append([]Profile{}, seeds...), custom...)
		mu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"profiles": all})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	var p Profile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Host = strings.TrimSpace(p.Host)
	if p.Name == "" || len(p.Name) > 64 || p.Host == "" || len(p.Host) > 253 || len(p.Ports) == 0 || len(p.Ports) > 32 {
		http.Error(w, `{"error":"name, host and 1–32 ports are required"}`, http.StatusBadRequest)
		return
	}
	seen := map[int]bool{}
	for _, port := range p.Ports {
		if port < 1 || port > 65535 || seen[port] {
			http.Error(w, `{"error":"ports must be unique integers from 1 to 65535"}`, http.StatusBadRequest)
			return
		}
		seen[port] = true
	}
	if p.TimeoutMS < 250 || p.TimeoutMS > 5000 { p.TimeoutMS = 1200 }
	p.ID = "custom-" + strconv.Itoa(len(custom)+1)
	p.Description = strings.TrimSpace(p.Description)
	mu.Lock()
	if len(custom) >= 20 { custom = custom[1:] }
	custom = append(custom, p)
	mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"profile": p})
}

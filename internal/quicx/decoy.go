package quicx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxDecoyBody = 256 << 10

type DecoySnapshot struct {
	Status int
	Header http.Header
	Body   []byte
}

type DecoyFetchFunc func(context.Context, string) (DecoySnapshot, error)

type DecoyOptions struct {
	Fetch      DecoyFetchFunc
	HTTPClient *http.Client
}

type Decoy struct {
	target string
	fetch  DecoyFetchFunc

	mu       sync.RWMutex
	snapshot DecoySnapshot
}

func NewDecoy(target string, opts DecoyOptions) (*Decoy, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("quicx: decoy target is required")
	}
	fetch := opts.Fetch
	if fetch == nil {
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}
		fetch = defaultDecoyFetcher(client)
	}
	return &Decoy{
		target: target,
		fetch:  fetch,
		snapshot: DecoySnapshot{
			Status: http.StatusNotFound,
			Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body:   []byte("<!doctype html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>"),
		},
	}, nil
}

func (d *Decoy) Refresh(ctx context.Context) error {
	snapshot, err := d.fetch(ctx, d.target)
	if err != nil {
		return err
	}
	snapshot = sanitizeDecoySnapshot(snapshot)
	d.mu.Lock()
	d.snapshot = snapshot
	d.mu.Unlock()
	return nil
}

func (d *Decoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	snapshot := DecoySnapshot{
		Status: d.snapshot.Status,
		Header: d.snapshot.Header.Clone(),
		Body:   d.snapshot.Body,
	}
	d.mu.RUnlock()
	for name, values := range snapshot.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(snapshot.Body)))
	w.WriteHeader(snapshot.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(snapshot.Body)
	}
}

func defaultDecoyFetcher(client *http.Client) DecoyFetchFunc {
	return func(ctx context.Context, target string) (DecoySnapshot, error) {
		u := &url.URL{Scheme: "https", Host: target, Path: "/"}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return DecoySnapshot{}, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return DecoySnapshot{}, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDecoyBody+1))
		if err != nil {
			return DecoySnapshot{}, err
		}
		return DecoySnapshot{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: body}, nil
	}
}

func sanitizeDecoySnapshot(snapshot DecoySnapshot) DecoySnapshot {
	if snapshot.Status < 200 || snapshot.Status >= 300 {
		snapshot.Status = http.StatusOK
	}
	if len(snapshot.Body) > maxDecoyBody {
		snapshot.Body = snapshot.Body[:maxDecoyBody]
	}
	snapshot.Body = append([]byte(nil), snapshot.Body...)
	safe := make(http.Header)
	for _, name := range []string{"Cache-Control", "Content-Language", "Content-Type", "ETag", "Last-Modified", "Vary"} {
		for _, value := range snapshot.Header.Values(name) {
			if strings.ContainsAny(value, "\r\n") {
				continue
			}
			safe.Add(name, value)
		}
	}
	snapshot.Header = safe
	return snapshot
}

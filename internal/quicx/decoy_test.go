package quicx

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestDecoyFetchesOnceAndServesManyRequests(t *testing.T) {
	var calls atomic.Int32
	d, err := NewDecoy("origin.example:443", DecoyOptions{
		Fetch: func(context.Context, string) (DecoySnapshot, error) {
			calls.Add(1)
			return DecoySnapshot{
				Status: http.StatusOK,
				Header: http.Header{"Content-Type": {"text/html"}},
				Body:   []byte("cached-decoy"),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		rr := httptest.NewRecorder()
		d.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://proxy.example/", nil))
		if rr.Code != http.StatusOK || rr.Body.String() != "cached-decoy" {
			t.Fatalf("response = %d %q", rr.Code, rr.Body.String())
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("origin fetches = %d, want 1", got)
	}
}

func TestDecoyBodyIsCappedAt256KiB(t *testing.T) {
	d, err := NewDecoy("origin.example:443", DecoyOptions{
		Fetch: func(context.Context, string) (DecoySnapshot, error) {
			return DecoySnapshot{Status: http.StatusOK, Body: bytes.Repeat([]byte{'x'}, 300<<10)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	d.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://proxy.example/", nil))
	if rr.Body.Len() != maxDecoyBody {
		t.Fatalf("body len = %d, want %d", rr.Body.Len(), maxDecoyBody)
	}
	if rr.Header().Get("Content-Length") != strconv.Itoa(maxDecoyBody) {
		t.Fatalf("content-length = %q", rr.Header().Get("Content-Length"))
	}
}

func TestDecoyStripsUnsafeHeadersAndNormalizesRedirect(t *testing.T) {
	d, err := NewDecoy("origin.example:443", DecoyOptions{
		Fetch: func(context.Context, string) (DecoySnapshot, error) {
			return DecoySnapshot{
				Status: http.StatusFound,
				Header: http.Header{
					"Content-Type": {"text/html"},
					"Location":     {"https://other.example/"},
					"Set-Cookie":   {"secret=1"},
					"Connection":   {"close"},
				},
				Body: []byte("moved"),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	d.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://proxy.example/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "text/html" {
		t.Fatal("safe content-type header missing")
	}
	for _, name := range []string{"Location", "Set-Cookie", "Connection"} {
		if rr.Header().Get(name) != "" {
			t.Fatalf("unsafe header %s retained", name)
		}
	}
}

func TestDecoyRefreshFailureRetainsLastGoodSnapshot(t *testing.T) {
	var fail atomic.Bool
	d, err := NewDecoy("origin.example:443", DecoyOptions{
		Fetch: func(context.Context, string) (DecoySnapshot, error) {
			if fail.Load() {
				return DecoySnapshot{}, errors.New("origin unavailable")
			}
			return DecoySnapshot{Status: http.StatusOK, Body: []byte("last-good")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := d.Refresh(context.Background()); err == nil {
		t.Fatal("refresh failure was hidden")
	}
	rr := httptest.NewRecorder()
	d.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://proxy.example/", nil))
	if rr.Body.String() != "last-good" {
		t.Fatalf("body = %q, want last-good", rr.Body.String())
	}
}

func TestDecoyHEADReturnsNoBodyWithCachedLength(t *testing.T) {
	d, err := NewDecoy("origin.example:443", DecoyOptions{
		Fetch: func(context.Context, string) (DecoySnapshot, error) {
			return DecoySnapshot{Status: http.StatusOK, Body: []byte("body")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	d.ServeHTTP(rr, httptest.NewRequest(http.MethodHead, "https://proxy.example/", nil))
	if rr.Body.Len() != 0 {
		t.Fatalf("HEAD body len = %d", rr.Body.Len())
	}
	if rr.Header().Get("Content-Length") != "4" {
		t.Fatalf("content-length = %q", rr.Header().Get("Content-Length"))
	}
}

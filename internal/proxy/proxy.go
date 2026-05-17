package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
	rghttp "github.com/nggurbanov/remnaguard/internal/httputil"
)

type Proxy struct {
	cfg            *config.Config
	client         *http.Client
	bearer         string
	publicAuth     string
	publicAuthName string
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func New(cfg *config.Config) (*Proxy, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.Upstream.AllowInsecureTLS} //nolint:gosec
	if cfg.Upstream.CustomCAFile != "" {
		pool, err := loadCAPool(cfg.Upstream.CustomCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.Upstream.MTLSCertFile != "" && cfg.Upstream.MTLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Upstream.MTLSCertFile, cfg.Upstream.MTLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	tr := &http.Transport{
		DisableCompression:    true,
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: cfg.Upstream.ResponseHeaderTimeout,
	}
	if tr.ResponseHeaderTimeout == 0 {
		tr.ResponseHeaderTimeout = 15 * time.Second
	}
	return &Proxy{
		cfg:            cfg,
		client:         &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		bearer:         cfg.ResolveBearer(),
		publicAuth:     strings.TrimSpace(os.Getenv(cfg.PublicSubs.AuthHeaderEnv)),
		publicAuthName: cfg.PublicSubs.AuthHeaderName,
	}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("custom CA file has no PEM certificates")
	}
	return pool, nil
}

func (p *Proxy) Client() *http.Client { return p.client }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request, path, rawQuery string, publicSub bool) {
	res, err := p.RoundTrip(w, r, path, rawQuery, publicSub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	p.WriteResponse(w, res, publicSub)
}

func (p *Proxy) RoundTrip(w http.ResponseWriter, r *http.Request, path, rawQuery string, publicSub bool) (*Response, error) {
	base, _ := url.Parse(p.cfg.Upstream.BaseURL)
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + path
	u.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		return nil, err
	}
	req.ContentLength = r.ContentLength
	req.GetBody = r.GetBody
	req.Header = r.Header.Clone()
	rghttp.StripHopByHop(req.Header)
	req.Header.Del("Authorization")
	req.Header.Set("Accept-Encoding", "identity")
	if !publicSub {
		req.Header.Set("Authorization", "Bearer "+p.bearer)
		for k, v := range p.cfg.Upstream.ExtraHeaders {
			req.Header.Set(k, v)
		}
	} else {
		filterHeaders(req.Header, p.cfg.PublicSubs.RequestHeaderAllowlist)
		for k, v := range p.cfg.PublicSubs.ExtraHeaders {
			req.Header.Set(k, v)
		}
		if p.publicAuthName != "" {
			req.Header.Set(p.publicAuthName, p.publicAuth)
		}
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := readLimited(res.Body, p.cfg.Limits.UpstreamBodyBytes)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: res.StatusCode, Header: res.Header.Clone(), Body: body}, nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(r)
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("upstream_response_too_large")
	}
	return body, nil
}

func (p *Proxy) WriteResponse(w http.ResponseWriter, res *Response, publicSub bool) {
	copyHeader(w.Header(), res.Header, publicSub, p.cfg.PublicSubs.ResponseHeaderAllowlist)
	if publicSub {
		for k, v := range p.cfg.PublicSubs.ExtraResponseHeaders {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(res.Body)
}

func copyHeader(dst, src http.Header, publicSub bool, allowed []string) {
	allowedSet := lowerSet(allowed)
	for k, vals := range src {
		lower := strings.ToLower(k)
		if protectedResponseHeader(lower) {
			continue
		}
		if publicSub && !allowedSet[lower] {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
	rghttp.StripHopByHop(dst)
}

func protectedResponseHeader(name string) bool {
	lower := strings.ToLower(name)
	if lower == "set-cookie" || lower == "authorization" || lower == "proxy-authenticate" || lower == "location" || strings.HasPrefix(lower, "x-debug") {
		return true
	}
	switch lower {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func filterHeaders(h http.Header, allowed []string) {
	allowedSet := lowerSet(allowed)
	for name := range h {
		if !allowedSet[strings.ToLower(name)] {
			h.Del(name)
		}
	}
}

func lowerSet(xs []string) map[string]bool {
	out := map[string]bool{}
	for _, x := range xs {
		out[strings.ToLower(x)] = true
	}
	return out
}

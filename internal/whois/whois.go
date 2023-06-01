// Package whois provides WHOIS functionality.
package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghio"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Empty does nothing.
type Empty struct{}

// Process implements the [home.WHOIS] interface for Empty.
func (Empty) Process(context.Context, netip.Addr) *Info {
	return nil
}

// Config is the configuration structure for Default.
type Config struct {
	// DialContext specifies the dial function for creating unencrypted TCP
	// connections.
	DialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// Server is the WHOIS server.
	Server string

	// Timeout is the timeout for WHOIS requests.
	Timeout time.Duration

	// CacheSize is the maximum size of the cache.  If it's zero, cache size is
	// unlimited.
	CacheSize uint

	// MaxConnReadSize is an upper limit in bytes for reading from net.Conn.
	MaxConnReadSize int64

	// MaxRedirects is the maximum redirects count.
	MaxRedirects int

	// MaxInfoLen is the maximum length of Info fields returned by Process.
	MaxInfoLen int

	// Port is the port for WHOIS requests.
	Port int
}

// Default provides WHOIS functionality.
type Default struct {
	// ipAddrs is the cache containing IP addresses of clients.  An active IP
	// address is resolved once again after it expires.  If IP address couldn't
	// be resolved, it stays here for some time to prevent further attempts to
	// resolve the same IP.
	ipAddrs cache.Cache

	// dialContext specifies the dial function for creating unencrypted TCP
	// connections.
	dialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// server is the WHOIS server.
	server string

	// timeout is the timeout for WHOIS requests.
	timeout time.Duration

	// maxConnReadSize is an upper limit in bytes for reading from net.Conn.
	maxConnReadSize int64

	// maxRedirects is the maximum redirects count.
	maxRedirects int

	// port for WHOIS requests.
	port int

	// maxInfoLen is the maximum length of Info fields returned by Process.
	maxInfoLen int
}

// New creates Default.
func New(config Config) (w *Default) {
	return &Default{
		server:      config.Server,
		dialContext: config.DialContext,
		timeout:     config.Timeout,
		ipAddrs: cache.New(cache.Config{
			EnableLRU: true,
			MaxCount:  config.CacheSize,
		}),
		maxConnReadSize: config.MaxConnReadSize,
		port:            config.Port,
	}
}

// trimValue cuts s and appends "...", if value length is equal or greater than
// max.  max must be greater than 3.
func trimValue(s string, max int) string {
	if len(s) <= max {
		return s
	}

	return s[:max-3] + "..."
}

// isWHOISComment returns true if the string is empty or is a WHOIS comment.
func isWHOISComment(s string) (ok bool) {
	return len(s) == 0 || s[0] == '#' || s[0] == '%'
}

// strmap is an alias for convenience.
type strmap = map[string]string

// whoisParse parses a subset of plain-text data from the WHOIS response into a
// string map.  maxLen is the maximum field length of returned map.
func whoisParse(data string, maxLen int) (m strmap) {
	m = strmap{}

	var orgname string
	lines := strings.Split(data, "\n")
	for _, l := range lines {
		if isWHOISComment(l) {
			continue
		}

		kv := strings.SplitN(l, ":", 2)
		if len(kv) != 2 {
			continue
		}

		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		if v == "" {
			continue
		}

		switch k {
		case "orgname", "org-name":
			k = "orgname"
			v = trimValue(v, maxLen)
			orgname = v
		case "city", "country":
			v = trimValue(v, maxLen)
		case "descr", "netname":
			k = "orgname"
			v = stringutil.Coalesce(orgname, v)
			orgname = v
		case "whois":
			k = "whois"
		case "referralserver":
			k = "whois"
			v = strings.TrimPrefix(v, "whois://")
		default:
			continue
		}

		m[k] = v
	}

	return m
}

// query sends request to a server and returns the response or error.
func (w *Default) query(ctx context.Context, target, serverAddr string) (data string, err error) {
	addr, _, _ := net.SplitHostPort(serverAddr)
	if addr == "whois.arin.net" {
		target = "n + " + target
	}

	conn, err := w.dialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return "", err
	}

	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	r, err := aghio.LimitReader(conn, w.maxConnReadSize)
	if err != nil {
		return "", err
	}

	_ = conn.SetReadDeadline(time.Now().Add(w.timeout))
	_, err = conn.Write([]byte(target + "\r\n"))
	if err != nil {
		return "", err
	}

	// This use of ReadAll is now safe, because we limited the conn Reader.
	var whoisData []byte
	whoisData, err = io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(whoisData), nil
}

// queryAll queries WHOIS server and handles redirects.
func (w *Default) queryAll(ctx context.Context, target string) (data string, err error) {
	port := strconv.Itoa(w.port)
	server := net.JoinHostPort(w.server, port)
	var resp string

	for i := 0; i != w.maxRedirects; i++ {
		resp, err = w.query(ctx, target, server)
		if err != nil {
			return "", err
		}

		log.Debug("whois: received response (%d bytes) from %s  IP:%s", len(resp), server, target)

		m := whoisParse(resp, w.maxInfoLen)
		redir, ok := m["whois"]
		if !ok {
			return resp, nil
		}

		redir = strings.ToLower(redir)

		_, _, err = net.SplitHostPort(redir)
		if err != nil {
			server = net.JoinHostPort(redir, port)
		} else {
			server = redir
		}

		log.Debug("whois: redirected to %s  IP:%s", redir, target)
	}

	return "", fmt.Errorf("whois: redirect loop")
}

// Process makes WHOIS request and returns WHOIS information or nil.
func (w *Default) Process(ctx context.Context, ip netip.Addr) (wi *Info) {
	if netutil.IsSpecialPurposeAddr(ip) {
		return nil
	}

	resp, err := w.queryAll(ctx, ip.String())
	if err != nil {
		log.Debug("whois: error: %s  IP:%s", err, ip)

		return nil
	}

	log.Debug("whois: IP:%s  response: %d bytes", ip, len(resp))

	m := whoisParse(resp, w.maxInfoLen)

	wi = &Info{
		City:    m["city"],
		Country: m["country"],
		Orgname: m["orgname"],
	}

	// Don't return an empty struct so that the frontend doesn't get
	// confused.
	if *wi == (Info{}) {
		return nil
	}

	return wi
}

// Info is the filtered WHOIS data for a runtime client.
type Info struct {
	City    string `json:"city,omitempty"`
	Country string `json:"country,omitempty"`
	Orgname string `json:"orgname,omitempty"`
}

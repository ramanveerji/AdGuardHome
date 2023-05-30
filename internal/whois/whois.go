// Package whois provides WHOIS functionality.
package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghio"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
)

const (
	defaultServer  = "whois.arin.net"
	defaultPort    = "43"
	maxValueLength = 250
	whoisTTL       = 1 * 60 * 60 // 1 hour
)

type callback func(netip.Addr, *RuntimeClientWHOISInfo)

// WHOIS - module context
type WHOIS struct {
	Ch chan netip.Addr

	// dialContext specifies the dial function for creating unencrypted TCP
	// connections.
	dialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// Contains IP addresses of clients
	// An active IP address is resolved once again after it expires.
	// If IP address couldn't be resolved, it stays here for some time to prevent further attempts to resolve the same IP.
	ipAddrs cache.Cache

	// TODO(a.garipov): Rewrite to use time.Duration.  Like, seriously, why?
	timeoutMsec uint
}

// InitWHOIS creates the WHOIS module context.
func InitWHOIS(customDialContext func(context.Context, string, string) (net.Conn, error)) (*WHOIS, func(callback)) {
	w := WHOIS{
		timeoutMsec: 5000,
		ipAddrs: cache.New(cache.Config{
			EnableLRU: true,
			MaxCount:  10000,
		}),
		dialContext: customDialContext,
		Ch:          make(chan netip.Addr, 255),
	}

	loop := func(cb callback) {
		for ip := range w.Ch {
			info := w.process(context.Background(), ip)
			if info == nil {
				continue
			}

			cb(ip, info)
		}
	}

	return &w, loop
}

// If the value is too large - cut it and append "..."
func trimValue(s string) string {
	if len(s) <= maxValueLength {
		return s
	}
	return s[:maxValueLength-3] + "..."
}

// isWHOISComment returns true if the string is empty or is a WHOIS comment.
func isWHOISComment(s string) (ok bool) {
	return len(s) == 0 || s[0] == '#' || s[0] == '%'
}

// strmap is an alias for convenience.
type strmap = map[string]string

// whoisParse parses a subset of plain-text data from the WHOIS response into
// a string map.
func whoisParse(data string) (m strmap) {
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
			v = trimValue(v)
			orgname = v
		case "city", "country":
			v = trimValue(v)
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

// MaxConnReadSize is an upper limit in bytes for reading from net.Conn.
const MaxConnReadSize = 64 * 1024

// Send request to a server and receive the response
func (w *WHOIS) query(ctx context.Context, target, serverAddr string) (data string, err error) {
	addr, _, _ := net.SplitHostPort(serverAddr)
	if addr == "whois.arin.net" {
		target = "n + " + target
	}

	conn, err := w.dialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	r, err := aghio.LimitReader(conn, MaxConnReadSize)
	if err != nil {
		return "", err
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(w.timeoutMsec) * time.Millisecond))
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

// Query WHOIS servers (handle redirects)
func (w *WHOIS) queryAll(ctx context.Context, target string) (string, error) {
	server := net.JoinHostPort(defaultServer, defaultPort)
	const maxRedirects = 5
	for i := 0; i != maxRedirects; i++ {
		resp, err := w.query(ctx, target, server)
		if err != nil {
			return "", err
		}
		log.Debug("whois: received response (%d bytes) from %s  IP:%s", len(resp), server, target)

		m := whoisParse(resp)
		redir, ok := m["whois"]
		if !ok {
			return resp, nil
		}
		redir = strings.ToLower(redir)

		_, _, err = net.SplitHostPort(redir)
		if err != nil {
			server = net.JoinHostPort(redir, defaultPort)
		} else {
			server = redir
		}

		log.Debug("whois: redirected to %s  IP:%s", redir, target)
	}
	return "", fmt.Errorf("whois: redirect loop")
}

// Request WHOIS information
func (w *WHOIS) process(ctx context.Context, ip netip.Addr) (wi *RuntimeClientWHOISInfo) {
	resp, err := w.queryAll(ctx, ip.String())
	if err != nil {
		log.Debug("whois: error: %s  IP:%s", err, ip)

		return nil
	}

	log.Debug("whois: IP:%s  response: %d bytes", ip, len(resp))

	m := whoisParse(resp)

	wi = &RuntimeClientWHOISInfo{
		City:    m["city"],
		Country: m["country"],
		Orgname: m["orgname"],
	}

	// Don't return an empty struct so that the frontend doesn't get
	// confused.
	if *wi == (RuntimeClientWHOISInfo{}) {
		return nil
	}

	return wi
}

// RuntimeClientWHOISInfo is the filtered WHOIS data for a runtime client.
type RuntimeClientWHOISInfo struct {
	City    string `json:"city,omitempty"`
	Country string `json:"country,omitempty"`
	Orgname string `json:"orgname,omitempty"`
}

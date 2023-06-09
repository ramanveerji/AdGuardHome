// Package whois provides WHOIS functionality.
package whois

import (
	"bytes"
	"context"
	"encoding/binary"
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

// Interface provides WHOIS functionality.
type Interface interface {
	// Process makes WHOIS request and returns WHOIS information or nil.
	Process(ctx context.Context, ip netip.Addr) (info *Info)
}

// Empty is an empty [Interface] implementation which does nothing.
type Empty struct{}

// type check
var _ Interface = (*Empty)(nil)

// Process implements the [Interface] interface for Empty.
func (Empty) Process(_ context.Context, _ netip.Addr) (_ *Info) {
	return nil
}

// Config is the configuration structure for Default.
type Config struct {
	// DialContext specifies the dial function for creating unencrypted TCP
	// connections.
	DialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// ServerAddr is the address of the WHOIS server.
	ServerAddr string

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
	Port uint16

	// IPTTL is the Time to Live value in seconds for cached IP addresses.
	IPTTL uint64
}

// Default is the default WHOIS information processor.
type Default struct {
	// ipAddrs is the cache containing IP addresses of clients.  An active IP
	// address is resolved once again after it expires.  If IP address couldn't
	// be resolved, it stays here for some time to prevent further attempts to
	// resolve the same IP.
	ipAddrs cache.Cache

	// dialContext connects to a remote server resolving hostname using our own
	// DNS server and unecrypted TCP connection.
	dialContext func(ctx context.Context, network, addr string) (conn net.Conn, err error)

	// serverAddr is the address of the WHOIS server.
	serverAddr string

	// portStr is the port for WHOIS requests.
	portStr string

	// timeout is the timeout for WHOIS requests.
	timeout time.Duration

	// maxConnReadSize is an upper limit in bytes for reading from net.Conn.
	maxConnReadSize int64

	// maxRedirects is the maximum redirects count.
	maxRedirects int

	// maxInfoLen is the maximum length of Info fields returned by Process.
	maxInfoLen int

	// ipTTL is the Time to Live value in seconds for cached IP addresses.
	ipTTL uint64
}

// New returns a new default WHOIS information processor. conf must not be nil.
func New(conf *Config) (w *Default) {
	return &Default{
		serverAddr:  conf.ServerAddr,
		dialContext: conf.DialContext,
		timeout:     conf.Timeout,
		ipAddrs: cache.New(cache.Config{
			EnableLRU: true,
			MaxCount:  conf.CacheSize,
		}),
		maxConnReadSize: conf.MaxConnReadSize,
		maxRedirects:    conf.MaxRedirects,
		portStr:         strconv.Itoa(int(conf.Port)),
		maxInfoLen:      conf.MaxInfoLen,
		ipTTL:           conf.IPTTL,
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

// isWHOISComment returns true if the data is empty or is a WHOIS comment.
func isWHOISComment(data []byte) (ok bool) {
	return len(data) == 0 || data[0] == '#' || data[0] == '%'
}

// whoisParse parses a subset of plain-text data from the WHOIS response into a
// string map.  maxLen is the maximum field length of returned map.
func whoisParse(data []byte, maxLen int) (info map[string]string) {
	info = map[string]string{}

	var orgname string
	lines := bytes.Split(data, []byte("\n"))
	for _, l := range lines {
		if isWHOISComment(l) {
			continue
		}

		before, after, found := bytes.Cut(l, []byte(":"))
		if !found {
			continue
		}

		key := strings.ToLower(string(before))
		val := strings.TrimSpace(string(after))
		if val == "" {
			continue
		}

		switch key {
		case "orgname", "org-name":
			key = "orgname"
			val = trimValue(val, maxLen)
			orgname = val
		case "city", "country":
			val = trimValue(val, maxLen)
		case "descr", "netname":
			key = "orgname"
			val = stringutil.Coalesce(orgname, val)
			orgname = val
		case "whois":
			key = "whois"
		case "referralserver":
			key = "whois"
			val = strings.TrimPrefix(val, "whois://")
		default:
			continue
		}

		info[key] = val
	}

	return info
}

// query sends request to a server and returns the response or error.
func (w *Default) query(ctx context.Context, target, serverAddr string) (data []byte, err error) {
	const arinWHOIS = "whois.arin.net"

	addr, _, _ := net.SplitHostPort(serverAddr)
	if addr == arinWHOIS {
		// Display type flags for query.
		//
		// See https://www.arin.net/resources/registry/whois/rws/api/#nicname-whois-queries.
		target = "n + " + target
	}

	conn, err := w.dialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.WithDeferred(err, conn.Close()) }()

	r, err := aghio.LimitReader(conn, w.maxConnReadSize)
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(w.timeout))
	_, err = io.WriteString(conn, target+"\r\n")
	if err != nil {
		return nil, err
	}

	// This use of ReadAll is now safe, because we limited the conn Reader.
	data, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// queryAll queries WHOIS server and handles redirects.
func (w *Default) queryAll(ctx context.Context, target string) (info map[string]string, err error) {
	server := net.JoinHostPort(w.serverAddr, w.portStr)
	var data []byte

	for i := 0; i < w.maxRedirects; i++ {
		data, err = w.query(ctx, target, server)
		if err != nil {
			return nil, err
		}

		log.Debug("whois: received response (%d bytes) from %s  IP:%s", len(data), server, target)

		info = whoisParse(data, w.maxInfoLen)
		redir, ok := info["whois"]
		if !ok {
			log.Debug("whois: IP:%s  response: %d bytes", target, len(data))

			return info, nil
		}

		redir = strings.ToLower(redir)

		_, _, err = net.SplitHostPort(redir)
		if err != nil {
			server = net.JoinHostPort(redir, w.portStr)
		} else {
			server = redir
		}

		log.Debug("whois: redirected to %s  IP:%s", redir, target)
	}

	return nil, fmt.Errorf("whois: redirect loop")
}

// type check
var _ Interface = (*Default)(nil)

// Process makes WHOIS request and returns WHOIS information or nil.
func (w *Default) Process(ctx context.Context, ip netip.Addr) (wi *Info) {
	if netutil.IsSpecialPurposeAddr(ip) {
		return nil
	}

	if w.IsProcessed(ip) {
		return nil
	}

	kv, err := w.queryAll(ctx, ip.String())
	if err != nil {
		log.Debug("whois: error: %s  IP:%s", err, ip)

		return nil
	}

	wi = &Info{
		City:    kv["city"],
		Country: kv["country"],
		Orgname: kv["orgname"],
	}

	// Don't return an empty struct so that the frontend doesn't get
	// confused.
	if *wi == (Info{}) {
		return nil
	}

	return wi
}

// IsProcessed returns true if the IP address was already processed.
func (w *Default) IsProcessed(ip netip.Addr) (ok bool) {
	ipBytes := ip.AsSlice()
	now := uint64(time.Now().Unix())

	expire := w.ipAddrs.Get(ipBytes)
	if len(expire) != 0 {
		exp := binary.BigEndian.Uint64(expire)
		if exp > now {
			return true
		}
	}

	expire = make([]byte, 8)
	binary.BigEndian.PutUint64(expire, now+w.ipTTL)
	_ = w.ipAddrs.Set(ipBytes, expire)

	return false
}

// Info is the filtered WHOIS data for a runtime client.
type Info struct {
	City    string `json:"city,omitempty"`
	Country string `json:"country,omitempty"`
	Orgname string `json:"orgname,omitempty"`
}

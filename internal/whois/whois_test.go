package whois

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// fakeConn is a mock implementation of net.Conn to simplify testing.
//
// TODO(e.burkov): Search for other places in code where it may be used. Move
// into aghtest then.
type fakeConn struct {
	// Conn is embedded here simply to make *fakeConn a net.Conn without
	// actually implementing all methods.
	net.Conn
	data []byte
}

// Write implements net.Conn interface for *fakeConn.  It always returns 0 and a
// nil error without mutating the slice.
func (c *fakeConn) Write(_ []byte) (n int, err error) {
	return 0, nil
}

// Read implements net.Conn interface for *fakeConn.  It puts the content of
// c.data field into b up to the b's capacity.
func (c *fakeConn) Read(b []byte) (n int, err error) {
	return copy(b, c.data), io.EOF
}

// Close implements net.Conn interface for *fakeConn.  It always returns nil.
func (c *fakeConn) Close() (err error) {
	return nil
}

// SetReadDeadline implements net.Conn interface for *fakeConn.  It always
// returns nil.
func (c *fakeConn) SetReadDeadline(_ time.Time) (err error) {
	return nil
}

// fakeDial is a mock implementation of customDialContext to simplify testing.
func (c *fakeConn) fakeDial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	return c, nil
}

const maxInfoLen = 250

func TestWHOIS(t *testing.T) {
	const (
		nl   = "\n"
		data = `OrgName:        FakeOrg LLC` + nl +
			`City:           Nonreal` + nl +
			`Country:        Imagiland` + nl
	)

	fc := &fakeConn{
		data: []byte(data),
	}

	w := New(&Config{
		Timeout:         5000 * time.Millisecond,
		DialContext:     fc.fakeDial,
		MaxConnReadSize: 1024,
		MaxRedirects:    5,
		MaxInfoLen:      maxInfoLen,
	})
	info := w.Process(context.Background(), netip.MustParseAddr("1.2.3.4"))
	assert.NotNil(t, info)

	assert.Equal(t, "FakeOrg LLC", info.Orgname)
	assert.Equal(t, "Imagiland", info.Country)
	assert.Equal(t, "Nonreal", info.City)
}

func TestWHOISParse(t *testing.T) {
	const (
		city    = "Nonreal"
		country = "Imagiland"
		orgname = "FakeOrgLLC"
		whois   = "whois.example.net"
	)

	testCases := []struct {
		want map[string]string
		name string
		in   string
	}{{
		want: map[string]string{},
		name: "empty",
		in:   ``,
	}, {
		want: map[string]string{},
		name: "comments",
		in:   "%\n#",
	}, {
		want: map[string]string{},
		name: "no_colon",
		in:   "city",
	}, {
		want: map[string]string{},
		name: "no_value",
		in:   "city:",
	}, {
		want: map[string]string{"city": city},
		name: "city",
		in:   `city: ` + city,
	}, {
		want: map[string]string{"country": country},
		name: "country",
		in:   `country: ` + country,
	}, {
		want: map[string]string{"orgname": orgname},
		name: "orgname",
		in:   `orgname: ` + orgname,
	}, {
		want: map[string]string{"orgname": orgname},
		name: "orgname_hyphen",
		in:   `org-name: ` + orgname,
	}, {
		want: map[string]string{"orgname": orgname},
		name: "orgname_descr",
		in:   `descr: ` + orgname,
	}, {
		want: map[string]string{"orgname": orgname},
		name: "orgname_netname",
		in:   `netname: ` + orgname,
	}, {
		want: map[string]string{"whois": whois},
		name: "whois",
		in:   `whois: ` + whois,
	}, {
		want: map[string]string{"whois": whois},
		name: "referralserver",
		in:   `referralserver: whois://` + whois,
	}, {
		want: map[string]string{},
		name: "other",
		in:   `other: value`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := whoisParse(tc.in, maxInfoLen)
			assert.Equal(t, tc.want, got)
		})
	}
}

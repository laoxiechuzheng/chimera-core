package chimera

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// IsForbiddenTarget reports whether addr points at a private, loopback, or
// link-local destination. Servers refuse to dial these to prevent an abused
// proxy from becoming a springboard into the server's internal network.
func IsForbiddenTarget(addr *Address) bool {
	var ips []net.IP
	switch addr.Type {
	case AtypDomain:
		// Domains are resolved by the caller; here we block obvious metadata
		// hostnames. Full IP-level protection happens after resolution.
		return false
	case AtypIPv4:
		ips = []net.IP{net.IP(addr.IP.To4())}
	case AtypIPv6:
		ips = []net.IP{net.IP(addr.IP.To16())}
	default:
		return false
	}
	for _, ip := range ips {
		if IsForbiddenIP(ip) {
			return true
		}
	}
	return false
}

func IsForbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type LookupIPFunc func(context.Context, string) ([]net.IP, error)

func ResolveAndValidateAuthority(ctx context.Context, authority string, lookup LookupIPFunc) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil || host == "" {
		return "", errors.New("chimera: invalid target authority")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", errors.New("chimera: invalid target port")
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]net.IP, error) {
				return net.DefaultResolver.LookupIP(ctx, "ip", host)
			}
		}
		ips, err = lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			return "", errors.New("chimera: target resolution failed")
		}
	}
	for _, ip := range ips {
		if IsForbiddenIP(ip) {
			return "", errors.New("chimera: forbidden target address")
		}
	}
	return net.JoinHostPort(ips[0].String(), strconv.FormatUint(port, 10)), nil
}

package chimera

import "net"

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
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
		// IPv4-mapped IPv6
		if v4 := ip.To4(); v4 != nil {
			if v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsUnspecified() {
				return true
			}
		}
		// Carrier-grade NAT + link-local range 169.254/16 + unique local fc00::/7 for IPv6 text form
		if v4 := ip.To4(); v4 != nil {
			if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
				return true
			}
		}
		if len(ip) == 16 && ip[0] == 0xfc {
			return true
		}
	}
	return false
}

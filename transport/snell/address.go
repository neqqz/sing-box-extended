package snell

import (
	"encoding/binary"
	"net"
	"strconv"
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	atypIPv4       = 1
	atypDomainName = 3
	atypIPv6       = 4
)

// socksAddr represents a SOCKS address as defined in RFC 1928 section 5.
type socksAddr []byte

func (a socksAddr) String() string {
	var host, port string
	switch a[0] {
	case atypDomainName:
		hostLen := uint16(a[1])
		host = string(a[2 : 2+hostLen])
		port = strconv.Itoa((int(a[2+hostLen]) << 8) | int(a[2+hostLen+1]))
	case atypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa((int(a[1+net.IPv4len]) << 8) | int(a[1+net.IPv4len+1]))
	case atypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa((int(a[1+net.IPv6len]) << 8) | int(a[1+net.IPv6len+1]))
	}
	return net.JoinHostPort(host, port)
}

// UDPAddr converts a socksAddr to *net.UDPAddr.
func (a socksAddr) UDPAddr() *net.UDPAddr {
	if len(a) == 0 {
		return nil
	}
	switch a[0] {
	case atypIPv4:
		var ip [net.IPv4len]byte
		copy(ip[0:], a[1:1+net.IPv4len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv4len : 1+net.IPv4len+2]))}
	case atypIPv6:
		var ip [net.IPv6len]byte
		copy(ip[0:], a[1:1+net.IPv6len])
		return &net.UDPAddr{IP: net.IP(ip[:]), Port: int(binary.BigEndian.Uint16(a[1+net.IPv6len : 1+net.IPv6len+2]))}
	}
	return nil
}

// splitSocksAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func splitSocksAddr(b []byte) socksAddr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}
	switch b[0] {
	case atypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case atypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case atypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil
	}
	if len(b) < addrLen {
		return nil
	}
	return b[:addrLen]
}

// parseAddr parses the address in string s. Returns nil if failed.
func parseAddr(s string) socksAddr {
	var addr socksAddr
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, 1+net.IPv4len+2)
			addr[0] = atypIPv4
			copy(addr[1:], ip4)
		} else {
			addr = make([]byte, 1+net.IPv6len+2)
			addr[0] = atypIPv6
			copy(addr[1:], ip)
		}
	} else {
		if len(host) > 255 {
			return nil
		}
		addr = make([]byte, 1+1+len(host)+2)
		addr[0] = atypDomainName
		addr[1] = byte(len(host))
		copy(addr[2:], host)
	}
	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}
	addr[len(addr)-2], addr[len(addr)-1] = byte(portnum>>8), byte(portnum)
	return addr
}

// parseAddrToSocksAddr parses a socks addr from net.Addr.
// This is a fast path of parseAddr(addr.String()).
func parseAddrToSocksAddr(addr net.Addr) socksAddr {
	var hostip net.IP
	var port int
	switch addr := addr.(type) {
	case *net.UDPAddr:
		hostip = addr.IP
		port = addr.Port
	case *net.TCPAddr:
		hostip = addr.IP
		port = addr.Port
	case nil:
		return nil
	}
	if hostip == nil {
		return parseAddr(addr.String())
	}
	var parsed socksAddr
	if ip4 := hostip.To4(); ip4.DefaultMask() != nil {
		parsed = make([]byte, 1+net.IPv4len+2)
		parsed[0] = atypIPv4
		copy(parsed[1:], ip4)
		binary.BigEndian.PutUint16(parsed[1+net.IPv4len:], uint16(port))
	} else {
		parsed = make([]byte, 1+net.IPv6len+2)
		parsed[0] = atypIPv6
		copy(parsed[1:], hostip)
		binary.BigEndian.PutUint16(parsed[1+net.IPv6len:], uint16(port))
	}
	return parsed
}

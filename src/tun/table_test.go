package tun

import (
	"net"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// nullLogger satisfies core.Logger without printing anything.
type nullLogger struct{}

func (nullLogger) Printf(string, ...interface{})  {}
func (nullLogger) Println(...interface{})          {}
func (nullLogger) Infof(string, ...interface{})   {}
func (nullLogger) Infoln(...interface{})           {}
func (nullLogger) Warnf(string, ...interface{})   {}
func (nullLogger) Warnln(...interface{})           {}
func (nullLogger) Errorf(string, ...interface{})  {}
func (nullLogger) Errorln(...interface{})          {}
func (nullLogger) Debugf(string, ...interface{})  {}
func (nullLogger) Debugln(...interface{})          {}
func (nullLogger) Traceln(...interface{})          {}

var _ core.Logger = nullLogger{}

func makeGW(b byte) net.IP {
	gw := make(net.IP, 16)
	gw[0] = 0x02
	gw[15] = b
	return gw
}

func gwAddr(b byte) address.Address {
	var a address.Address
	copy(a[:], makeGW(b))
	return a
}

// TestTable_UpdateAndLookup verifies that a route inserted via Update is found
// by Lookup for an address that falls within that prefix.
func TestTable_UpdateAndLookup(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	gw := makeGW(1)
	tbl.Update(dst, gw)

	got, ok := tbl.Lookup(net.ParseIP("10.1.2.3"))
	if !ok {
		t.Fatal("Lookup returned no result for address in inserted prefix")
	}
	if got != gwAddr(1) {
		t.Fatalf("Lookup returned wrong gateway: got %v, want %v", got, gwAddr(1))
	}
}

// TestTable_LookupNoMatch verifies that Lookup returns false for an address
// that has no matching prefix.
func TestTable_LookupNoMatch(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	tbl.Update(dst, makeGW(1))

	_, ok := tbl.Lookup(net.ParseIP("192.168.1.1"))
	if ok {
		t.Fatal("Lookup returned a result for an address with no matching prefix")
	}
}

// TestTable_Remove verifies that a route deleted via Remove is no longer found.
func TestTable_Remove(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	tbl.Update(dst, makeGW(1))
	tbl.Remove(dst)

	_, ok := tbl.Lookup(net.ParseIP("10.1.2.3"))
	if ok {
		t.Fatal("Lookup returned a result after the route was removed")
	}
}

// TestTable_LongestPrefixMatch verifies that the most-specific (longest)
// prefix wins when multiple prefixes match.
func TestTable_LongestPrefixMatch(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, broad, _ := net.ParseCIDR("10.0.0.0/8")
	_, narrow, _ := net.ParseCIDR("10.1.0.0/16")
	tbl.Update(broad, makeGW(1))
	tbl.Update(narrow, makeGW(2))

	got, ok := tbl.Lookup(net.ParseIP("10.1.2.3"))
	if !ok {
		t.Fatal("Lookup returned no result")
	}
	if got != gwAddr(2) {
		t.Fatalf("Expected narrow /16 gateway (2), got %v", got)
	}

	got, ok = tbl.Lookup(net.ParseIP("10.2.3.4"))
	if !ok {
		t.Fatal("Lookup returned no result for broad prefix")
	}
	if got != gwAddr(1) {
		t.Fatalf("Expected broad /8 gateway (1), got %v", got)
	}
}

// TestTable_IPv6 verifies that IPv6 routes work correctly.
func TestTable_IPv6(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("2001:db8::/32")
	tbl.Update(dst, makeGW(7))

	got, ok := tbl.Lookup(net.ParseIP("2001:db8::1"))
	if !ok {
		t.Fatal("IPv6 Lookup returned no result")
	}
	if got != gwAddr(7) {
		t.Fatalf("IPv6 Lookup returned wrong gateway: %v", got)
	}
}

// TestTable_UpdateOverwrite verifies that updating an existing prefix replaces
// the gateway.
func TestTable_UpdateOverwrite(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	tbl.Update(dst, makeGW(1))
	tbl.Update(dst, makeGW(2))

	got, ok := tbl.Lookup(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Fatal("Lookup returned no result")
	}
	if got != gwAddr(2) {
		t.Fatalf("Expected updated gateway (2), got %v", got)
	}
}

// TestTable_InvalidGW verifies that Update silently ignores non-IPv6 gateways.
func TestTable_InvalidGW(t *testing.T) {
	tbl := NewTable(nullLogger{})

	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	tbl.Update(dst, net.ParseIP("192.168.1.1").To4()) // 4-byte, should be ignored

	_, ok := tbl.Lookup(net.ParseIP("10.0.0.1"))
	if ok {
		t.Fatal("Lookup should not have matched after inserting non-IPv6 gateway")
	}
}

// BenchmarkLookupIPv4 measures the Lookup hot path for IPv4 addresses.
func BenchmarkLookupIPv4(b *testing.B) {
	tbl := NewTable(nullLogger{})
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	tbl.Update(dst, makeGW(1))

	ip := net.ParseIP("10.1.2.3")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tbl.Lookup(ip)
	}
}

// BenchmarkLookupIPv6 measures the Lookup hot path for IPv6 addresses.
func BenchmarkLookupIPv6(b *testing.B) {
	tbl := NewTable(nullLogger{})
	_, dst, _ := net.ParseCIDR("2001:db8::/32")
	tbl.Update(dst, makeGW(1))

	ip := net.ParseIP("2001:db8::1")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tbl.Lookup(ip)
	}
}

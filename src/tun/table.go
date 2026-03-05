package tun

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/armon/go-radix"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// Table provides a lock-free LPM (longest-prefix-match) routing table.
// Reads (Lookup) load the tree via an atomic pointer and are never blocked by
// concurrent writes.  Writes (Update/Remove) use a copy-on-write strategy
// (RCU): a new radix tree is built under a write mutex and then swapped in
// atomically, so the data plane never waits on the control plane.
type Table struct {
	writeMu sync.Mutex   // Serialises concurrent writers
	tree    atomic.Value // Stores *radix.Tree; read without any lock
	log     core.Logger
}

func NewTable(log core.Logger) *Table {
	t := &Table{log: log}
	t.tree.Store(radix.New())
	return t
}

// ipToKey converts an IP address into a radix-tree key (a string of '0'/'1'
// characters) using a fixed-size stack buffer so that no heap allocations from
// fmt.Sprintf or repeated string concatenation occur.
// prefixLen specifies how many bits to include; pass len(ip)*8 for a full
// host address lookup.
func ipToKey(ip net.IP, prefixLen int) string {
	var buf [128]byte
	n := 0
outer:
	for _, b := range ip {
		for bit := 7; bit >= 0; bit-- {
			if n >= prefixLen {
				break outer
			}
			if b&(1<<uint(bit)) != 0 {
				buf[n] = '1'
			} else {
				buf[n] = '0'
			}
			n++
		}
	}
	return string(buf[:n])
}

// normalizeIP returns the 4-byte form of an IPv4 address, or the address
// unchanged for IPv6.  This ensures IPv4 and IPv4-in-IPv6 addresses share
// the same key space in the radix tree.
func normalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip
}

func (t *Table) Update(dst *net.IPNet, gw net.IP) {
	var yggGw address.Address
	if len(gw) == 16 {
		copy(yggGw[:], gw)
	} else {
		return
	}

	ip := normalizeIP(dst.IP)
	ones, _ := dst.Mask.Size()
	key := ipToKey(ip, ones)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	// RCU write: copy the current tree, insert the new entry, then swap.
	newTree := t.cloneTree()
	newTree.Insert(key, yggGw)
	t.tree.Store(newTree)
	t.log.Debugf("Table: Added route %s -> %s", dst.String(), gw.String())
}

func (t *Table) Remove(dst *net.IPNet) {
	ip := normalizeIP(dst.IP)
	ones, _ := dst.Mask.Size()
	key := ipToKey(ip, ones)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	// RCU write: copy the current tree, delete the entry, then swap.
	newTree := t.cloneTree()
	newTree.Delete(key)
	t.tree.Store(newTree)
	t.log.Debugf("Table: Removed route %s", dst.String())
}

func (t *Table) Lookup(ip net.IP) (address.Address, bool) {
	lookupIP := normalizeIP(ip)
	key := ipToKey(lookupIP, len(lookupIP)*8)

	// RCU read: atomic load, no lock required.
	tree := t.tree.Load().(*radix.Tree)
	_, val, found := tree.LongestPrefix(key)
	if !found {
		return address.Address{}, false
	}
	return val.(address.Address), true
}

// cloneTree returns a new *radix.Tree containing all entries from the current
// tree.  Must be called with writeMu held.
func (t *Table) cloneTree() *radix.Tree {
	newTree := radix.New()
	t.tree.Load().(*radix.Tree).Walk(func(s string, v interface{}) bool {
		newTree.Insert(s, v)
		return false
	})
	return newTree
}

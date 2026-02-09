package tun

import (
	"fmt"
	"net"
	"sync"

	"github.com/armon/go-radix"
	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

type Table struct {
	mutex sync.RWMutex
	tree  *radix.Tree
	log   core.Logger
}

func NewTable(log core.Logger) *Table {
	return &Table{
		tree: radix.New(),
		log:  log,
	}
}

func currentIPToBitString(ip net.IP, mask net.IPMask) string {
	ip4 := ip.To4()
	if ip4 != nil {
		ip = ip4
	}
	
	bits := ""
	for _, b := range ip {
		bits += fmt.Sprintf("%08b", b)
	}

	if mask != nil {
		ones, _ := mask.Size()
		if ones < len(bits) {
			bits = bits[:ones]
		}
	}
	return bits
}

func (t *Table) Update(dst *net.IPNet, gw net.IP) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	var yggGw address.Address
	if len(gw) == 16 {
		copy(yggGw[:], gw)
	} else {
		return
	}

	key := currentIPToBitString(dst.IP, dst.Mask)
	t.tree.Insert(key, yggGw)
	t.log.Debugf("Table: Added route %s -> %s", dst.String(), gw.String())
}

func (t *Table) Remove(dst *net.IPNet) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	key := currentIPToBitString(dst.IP, dst.Mask)
	t.tree.Delete(key)
	t.log.Debugf("Table: Removed route %s", dst.String())
}

func (t *Table) Lookup(ip net.IP) (address.Address, bool) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	key := currentIPToBitString(ip, nil)
	_, val, found := t.tree.LongestPrefix(key)
	if !found {
		return address.Address{}, false
	}
	return val.(address.Address), true
}

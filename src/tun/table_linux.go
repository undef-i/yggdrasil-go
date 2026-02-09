//go:build linux

package tun

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (t *Table) Start() {
	t.log.Debugln("Table: Starting netlink watcher")
	go func() {
		routes4, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err == nil {
			for _, r := range routes4 {
				route := r
				t.handleRoute(&route)
			}
		}
		routes6, err := netlink.RouteList(nil, netlink.FAMILY_V6)
		if err == nil {
			for _, r := range routes6 {
				route := r
				t.handleRoute(&route)
			}
		}

		ch := make(chan netlink.RouteUpdate)
		done := make(chan struct{})

		if err := netlink.RouteSubscribe(ch, done); err != nil {
			t.log.Warnf("Table: Failed to subscribe to netlink: %s", err)
			return
		}
		
		for update := range ch {
			switch update.Type {
			case unix.RTM_NEWROUTE:
				t.handleRoute(&update.Route)
			case unix.RTM_DELROUTE:
				if update.Route.Dst != nil {
					t.Remove(update.Route.Dst)
				}
			}
		}
	}()
}

func (t *Table) handleRoute(r *netlink.Route) {
	gw := r.Gw
	if gw == nil && r.Via != nil {
		if via, ok := r.Via.(*netlink.Via); ok {
			gw = via.Addr
		}
	}

	if gw == nil {
		return
	}
	
	if len(gw) != 16 {
		return
	}

	if gw[0]&0xfe != 0x02 {
		return
	}

	dst := r.Dst
	if dst == nil {
		if r.Family == netlink.FAMILY_V4 {
			dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		} else {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
	}
	
	t.Update(dst, gw)
}

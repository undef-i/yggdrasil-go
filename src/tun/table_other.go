//go:build !linux

package tun

func (t *Table) Start() {
	t.log.Debugln("Table: Not supported on this platform (Linux only)")
}

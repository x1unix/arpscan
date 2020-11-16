package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	sysfsPath            = "/sys/class/net"
	sysfsVirtualDevsPath = "/sys/devices/virtual"
)

func isPhysicalNIC(nic net.Interface) bool {
	// dirty workaround to check if NIC is not virtual.
	//
	// This also can be done with ioctl and flag IIF_LOWER_UP check but this is a faster way.
	dstPath, err := os.Readlink(filepath.Join(sysfsPath, nic.Name))
	if err != nil {
		return false
	}

	absPath := filepath.Clean(filepath.Join(sysfsPath, dstPath))
	return !strings.HasPrefix(absPath, sysfsVirtualDevsPath)
}

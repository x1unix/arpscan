// +build !linux

package main

import "net"

func isPhysicalNIC(nic net.Interface) bool {
	// stub!
	return true
}

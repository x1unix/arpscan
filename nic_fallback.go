// +build !linux

package main

func isPhysicalNIC(nic net.Interface) bool {
	// stub!
	return true
}

package main

import (
    "testing"
    "net"
)

func Test_findIPv6Addresses_Empty_Slice(t *testing.T) {
    emptySlice := []net.IP{}
    ret := findIPv6Addresses(emptySlice)
    if len(ret) != 0 {
        t.Fatalf("The function should have returned empty slice")
    }
}

func Test_findIPv6Addresses_IPv4(t *testing.T) {
    invalidIPs := []net.IP{net.ParseIP("127.0.0.1")}
    ret := findIPv6Addresses(invalidIPs)
    if len(ret) != 0 {
        t.Fatalf("The function should have returned empty slice")
    }
}

func Test_findIPv6Addresses_Valid_IPv6(t *testing.T) {
    validIPs := []net.IP{net.ParseIP("fe80::1")}
    ret := findIPv6Addresses(validIPs)
    if len(ret) != 1 {
        t.Fatalf("The function should have returned 1 entry")
    }
}

func Test_findIPv6Addresses_Invalid_IPv6(t *testing.T) {
    invalidIPs := []net.IP{net.ParseIP("ga:rb:ag::1")}
    ret := findIPv6Addresses(invalidIPs)
    if len(ret) != 0 {
        t.Fatalf("The function should have returned 0 entry")
    }
}

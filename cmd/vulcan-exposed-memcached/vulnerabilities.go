/*
Copyright 2021 Adevinta
*/

package main

import report "github.com/adevinta/vulcan-report"

var exposedMemcachedVuln = report.Vulnerability{
	Summary: "Exposed Memcached Server",
	Description: "Memcached is a server meant to be run in trusted networks." +
		" Otherwise, a remote attacker can execute memcached commands (like adding" +
		" or removing items from the cache, etc.) against the server.\n\n" +
		"Apart from that, if the UDP port of the memcached is exposed" +
		" the server is vulnerable to be used it in UDP Amplification Attacks (DDoS).",
	Score: report.SeverityThresholdHigh,
	CWEID: 284,
	Recommendations: []string{
		"Do not expose the memcached server to the Internet.",
		"If running in an internal trusted network, implement authentication.",
		"Disable the UDP port of the memcached server.",
	},
	References: []string{
		"https://github.com/memcached/memcached/wiki/SASLHowto",
		"https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
		"https://tools.cisco.com/security/center/viewAlert.x?alertId=57020&vs_f=Alert%20RSS&vs_cat=Security%20Intelligence&vs_type=RSS&vs_p=Memcached%20Network%20Message%20Volume%20Denial%20of%20Service%20Vulnerability&vs_k=1",
	},
}

package main

import (
	"github.com/adamy318/dns-record-updater/updater"
)

func main() {
	user := "pi"
	server := &updater.DNSServer{
		Hostname: "pi.hole",
	}

	updater.SSHConnect(updater.GetSSHConfig(user), *server)

}

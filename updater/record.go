package updater

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type DNSServer struct {
	Hostname string
}

type DNSRecord struct {
	IPAddress net.IP
	FQDN      string
	Hostname  string
}

var (
	home = os.Getenv("HOME")
)

func getHostKey(host string) (ssh.PublicKey, error) {
	file, err := os.Open(filepath.Join(home, ".ssh", "known_hosts"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, errors.New(fmt.Sprintf("error parsing %q: %v", fields[2], err))
			}
			break
		}
	}

	if hostKey == nil {
		return nil, errors.New(fmt.Sprintf("no hostkey for %s", host))
	}
	return hostKey, nil
}

func GetSSHConfig(user string) *ssh.ClientConfig {
	hostKey, err := getHostKey("pi.hole")
	if err != nil {
		log.Fatal(err)
	}

	key, err := ioutil.ReadFile(filepath.Join(home, ".ssh", "id_rsa"))
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	return &ssh.ClientConfig{User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}
}

func GetDNSRecord(ip net.IP, hostname, string, domain string) *DNSRecord {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter IP address: ")
	ipString, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(strings.Split(ipString, ".")) != 4 {
		log.Fatal("did not enter valid IP address")
	}
	ip = net.ParseIP(ipString)

	fmt.Print("Enter hostname: ")
	hostname, err = reader.ReadString('\n')
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(strings.Fields(hostname)) > 1 {
		log.Fatal("did not enter valid hostname")
	}

	return &DNSRecord{ip, hostname + "." + domain, hostname}

}

func SSHConnect(config *ssh.ClientConfig, hostname DNSServer) {

	client, err := ssh.Dial("tcp", hostname.Hostname+":22", config)
	if err != nil {
		log.Fatalf("unable to connect to server: %v", err)
	}
	fmt.Println("we are inside boys")
	defer client.Close()
}

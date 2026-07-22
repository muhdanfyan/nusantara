package network

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DetectPublicIP tries to find the server's public IP using external services
func DetectPublicIP() (string, error) {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipinfo.io/ip",
	}

	client := http.Client{Timeout: 5 * time.Second}

	for _, endpoint := range endpoints {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}

		// ✅ FIXED: Close langsung, bukan defer di dalam loop (cegah memory leak)
		if resp.StatusCode == http.StatusOK {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				ip := strings.TrimSpace(string(bodyBytes))
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
		} else {
			resp.Body.Close()
		}
	}
	return "", fmt.Errorf("failed to detect public IP")
}

// DetectPrivateIP gets the primary local IP address
func DetectPrivateIP() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		// Fallback to iterating interfaces
		return getFallbackPrivateIP()
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func getFallbackPrivateIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			// Skip loopback dan IPv6
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // bukan IPv4
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no private IP found")
}

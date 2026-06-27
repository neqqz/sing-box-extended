package v2raygrpclite

import "strings"

func grpcPath(serviceName string) string {
	if strings.Contains(serviceName, "/") {
		return serviceName
	}
	return "/" + serviceName + "/Tun"
}

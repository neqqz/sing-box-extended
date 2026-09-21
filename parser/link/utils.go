package link

import (
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/common"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
)

func shadowsocksPluginName(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[:index]
	}
	return plugin
}

func shadowsocksPluginOptions(plugin string) string {
	if index := strings.Index(plugin, ";"); index != -1 {
		return plugin[index+1:]
	}
	return ""
}

func v2rayTransportWsPath(WebsocketOptions *option.V2RayWebsocketOptions, path string) {
	reg := regexp.MustCompile(`^(.*?)(?:\?ed=(\d*))?$`)
	result := reg.FindStringSubmatch(path)
	if result == nil {
		WebsocketOptions.Path = path
		return
	}
	WebsocketOptions.Path = result[1]
	if result[2] != "" {
		WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		WebsocketOptions.MaxEarlyData = common.StringToType[uint32](result[2])
	}
}

func v2rayTransportWs(host string, path string) option.V2RayWebsocketOptions {
	var WebsocketOptions option.V2RayWebsocketOptions
	if host != "" {
		WebsocketOptions.Headers = common.StringToType[badoption.HTTPHeader](F.ToString("Host: ", host))
	}
	if path != "" {
		v2rayTransportWsPath(&WebsocketOptions, path)
	}
	return WebsocketOptions
}

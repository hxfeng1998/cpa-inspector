package main

import (
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// 宿主的 passthrough-headers 决定上游响应头是否会下发给客户端，但插件接口不暴露宿主配置。
// 这里尽力而为地读取工作目录下的 config.yaml（CPA 的默认位置，官方 Docker 镜像亦然）；
// 读不到就如实报告"未知"，绝不猜测。

const (
	passthroughOn      = "on"
	passthroughOff     = "off"
	passthroughUnknown = "unknown"
)

var hostConfigPath = "config.yaml" // 测试里会替换

var hostConfigCache struct {
	sync.Mutex
	path    string
	modTime time.Time
	checked time.Time
	value   string
}

func hostPassthroughHeaders() string {
	c := &hostConfigCache
	c.Lock()
	defer c.Unlock()
	if c.path == hostConfigPath && time.Since(c.checked) < 5*time.Second {
		return c.value
	}
	c.checked = time.Now()
	info, err := os.Stat(hostConfigPath)
	if err != nil {
		c.path, c.value = hostConfigPath, passthroughUnknown
		return c.value
	}
	if c.path == hostConfigPath && info.ModTime().Equal(c.modTime) && c.value != "" {
		return c.value
	}
	c.path, c.modTime, c.value = hostConfigPath, info.ModTime(), passthroughUnknown
	raw, err := os.ReadFile(hostConfigPath)
	if err != nil {
		return c.value
	}
	var doc struct {
		Port        *int  `yaml:"port"` // 用来确认这确实是一份 CPA 配置，而不是别的 config.yaml
		Passthrough *bool `yaml:"passthrough-headers"`
	}
	if yaml.Unmarshal(raw, &doc) != nil || doc.Port == nil {
		return c.value
	}
	c.value = passthroughOff // 宿主默认关闭
	if doc.Passthrough != nil && *doc.Passthrough {
		c.value = passthroughOn
	}
	return c.value
}

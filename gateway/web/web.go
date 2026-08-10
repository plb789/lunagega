package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// 嵌入web目录下的静态文件
//
//go:embed dashboard.html
var dashboardFS embed.FS

// 获取嵌入的文件系统
func GetFileSystem() http.FileSystem {
	sub, err := fs.Sub(dashboardFS, ".")
	if err != nil {
		panic("加载嵌入式Web文件失败: " + err.Error())
	}
	return http.FS(sub)
}

// 获取仪表盘HTML内容
func GetDashboardHTML() []byte {
	data, err := dashboardFS.ReadFile("dashboard.html")
	if err != nil {
		return []byte("<html><body>加载页面失败</body></html>")
	}
	return data
}

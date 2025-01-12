package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	// 定义启动参数
	port := flag.Int("port", 8080, "监听端口")
	targetHost := flag.String("targethost", "", "代理目标域名")
	flag.Parse()

	if *targetHost == "" {
		log.Fatal("必须提供 -targethost 参数")
	}

	log.Printf("代理服务启动，监听端口: %d, 目标域名: %s\n", *port, *targetHost)

	// 启动 HTTP 服务
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, *targetHost)
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request, targetHost string) {
	// 解析请求的 URL
	requestURL := r.URL
	protocol := "https"
	if requestURL.Scheme == "http" {
		protocol = "http"
	}
	// 如果目标主机没有 IP 格式，默认切换为 HTTPS 协议
	if protocol == "http" && !isIPAddress(targetHost) {
		protocol = "https"
	}
	// 设置目标地址
	requestURL.Scheme = protocol
	requestURL.Host = targetHost

	// 过滤请求头
	headers := make(http.Header)
	for key, values := range r.Header {
		if strings.HasPrefix(key, "cf-") || strings.HasPrefix(key, "x-") ||
			key == "Connection" || key == "Origin" || key == "Referer" ||
			key == "Host" || key == "Authority" || key == "Link" {
			continue
		}
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	headers.Set("Host", targetHost)

	// 创建代理请求
	proxyRequest, err := http.NewRequest(r.Method, requestURL.String(), r.Body)
	if err != nil {
		http.Error(w, "创建代理请求失败", http.StatusInternalServerError)
		log.Println("创建代理请求失败:", err)
		return
	}
	proxyRequest.Header = headers

	// 执行代理请求
	client := &http.Client{}
	resp, err := client.Do(proxyRequest)
	if err != nil {
		http.Error(w, "代理请求失败", http.StatusInternalServerError)
		log.Println("代理请求失败:", err)
		return
	}
	defer resp.Body.Close()

	// 转发响应
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("转发响应内容失败:", err)
	}
}

// 判断是否为 IP 地址
func isIPAddress(host string) bool {
	for _, ch := range host {
		if !(ch == '.' || ch == ':' || (ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}

// 复制 HTTP 响应头
func copyHeaders(dest, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

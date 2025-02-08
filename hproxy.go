package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	port         = 8089
	httpDir      = "http" // 存放 HTTP 文件的子目录
	routeXMLPath = "hide/route.xml"
)

func main() {
	// 设置日志同时输出到文件和控制台
	logFile, err := os.OpenFile("server.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.LstdFlags | log.Lshortfile) // 日志中包含时间戳和文件:行号

	// 如果 http 目录不存在，则创建它
	if _, err := os.Stat(httpDir); os.IsNotExist(err) {
		if err := os.Mkdir(httpDir, 0755); err != nil {
			log.Fatalf("创建 http 目录失败: %v", err)
		}
	}

	// HTTP 请求处理函数
	http.HandleFunc("/", requestHandler)

	// 启动服务器
	addr := fmt.Sprintf(":%d", port)
	log.Printf("服务器已启动，端口号 %d", port)
	log.Printf("针对 /%s 的请求将返回 route.xml", routeXMLPath)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatalf("ListenAndServe 错误: %v", err)
	}
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()
    log.Printf("收到请求: %s %s 来自 %s", r.Method, r.URL, r.RemoteAddr)

    // 检查请求路径是否匹配特定路径
    if r.URL.Path == "/"+routeXMLPath && r.Method == "GET" {
        serveRouteXML(w, r)
    } else {
        // 处理 POST 请求
        if r.Method == "POST" {
            body, err := ioutil.ReadAll(r.Body)
            if err != nil {
                log.Printf("读取请求体失败: %v", err)
                http.Error(w, "读取请求体失败", http.StatusInternalServerError)
                return
            }
            defer r.Body.Close()

            // 解析 POST 数据
            values, err := url.ParseQuery(string(body))
            if err != nil {
                log.Printf("解析 POST 数据失败: %v", err)
                http.Error(w, "解析 POST 数据失败", http.StatusBadRequest)
                return
            }

            // 获取并解码 msg 参数
            msgEncoded := values.Get("msg")
            msgDecoded, err := url.QueryUnescape(msgEncoded) // 进行 URL 解码
            if err != nil {
                log.Printf("解码 msg 参数失败: %v", err)
                http.Error(w, "解码 msg 参数失败", http.StatusBadRequest)
                return
            }
            // 输出解码后的 msg 数据
            log.Printf("收到 POST 请求体数据: msg_id=%s&msg=%s", values.Get("msg_id"), msgDecoded)

            msgID := values.Get("msg_id")
            if msgID == "" {
                log.Printf("未找到 msg_id 参数")
                http.Error(w, "未找到 msg_id 参数", http.StatusBadRequest)
                return
            }

            // 根据 msg_id 构建 JSON 文件路径
            jsonFilePath := filepath.Join(httpDir, msgID+".json")

            // 检查 JSON 文件是否存在
            if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
                log.Printf("文件 %s 不存在", jsonFilePath)
                // 返回自定义的错误信息
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK) //这里可以改为其他的状态码
                w.Write([]byte(`{"errorCode":-13,"errorMsg":"`+msgID+`"}`))
                return
            }

            // 读取 JSON 文件内容
            jsonContent, err := ioutil.ReadFile(jsonFilePath)
            if err != nil {
                log.Printf("读取文件 %s 失败: %v", jsonFilePath, err)
                http.Error(w, "服务器内部错误", http.StatusInternalServerError)
                return
            }

            // 设置响应头并返回 JSON 内容
            w.Header().Set("Content-Type", "application/json")
            w.Write(jsonContent)

            log.Printf("成功返回 %s 给 %s", jsonFilePath, r.RemoteAddr)

        } else {
            http.NotFound(w, r)
        }
    }

    duration := time.Since(startTime)
    log.Printf("请求处理耗时 %v", duration)
}

func serveRouteXML(w http.ResponseWriter, r *http.Request) {
	// 构建 route.xml 的完整路径
	xmlFilePath := filepath.Join(httpDir, "route.xml")

	// 检查 route.xml 是否存在
	if _, err := os.Stat(xmlFilePath); os.IsNotExist(err) {
		log.Printf("route.xml 文件不存在: %s", xmlFilePath)
		http.NotFound(w, r)
		return
	}

	// 读取 route.xml 的内容
	xmlContent, err := ioutil.ReadFile(xmlFilePath)
	if err != nil {
		log.Printf("读取 route.xml 文件失败: %v", err)
		http.Error(w, "服务器内部错误", http.StatusInternalServerError)
		return
	}

	// 设置响应头并发送 XML 内容
	w.Header().Set("Content-Type", "application/xml")
	w.Write(xmlContent)

	log.Printf("成功返回 route.xml 给 %s", r.RemoteAddr)
}

package main

import (
    "encoding/json"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "github.com/joho/godotenv"
)

// 配置结构体
type Config struct {
    ProxyHostname       string `json:"PROXY_HOSTNAME"`
    ProxyProtocol       string `json:"PROXY_PROTOCOL"`
    PathnameRegex       string `json:"PATHNAME_REGEX"`
    UAWhitelistRegex    string `json:"UA_WHITELIST_REGEX"`
    UABlacklistRegex    string `json:"UA_BLACKLIST_REGEX"`
    IPWhitelistRegex    string `json:"IP_WHITELIST_REGEX"`
    IPBlacklistRegex    string `json:"IP_BLACKLIST_REGEX"`
    RegionWhitelistRegex string `json:"REGION_WHITELIST_REGEX"`
    RegionBlacklistRegex string `json:"REGION_BLACKLIST_REGEX"`
    URL302              string `json:"URL302"`
    Debug               string `json:"DEBUG"`
}

// 读取 proxyconfig.json 文件配置
func loadConfig() Config {
    var config Config

    file, err := os.Open("proxyconfig.json")
    if err != nil {
        log.Println("proxyconfig.json 文件不存在，尝试加载 .env 文件")
        err = godotenv.Load(".env")
        if err != nil {
            log.Fatal("Error loading .env file")
        }

        config.ProxyHostname = os.Getenv("PROXY_HOSTNAME")
        config.ProxyProtocol = os.Getenv("PROXY_PROTOCOL")
        config.PathnameRegex = os.Getenv("PATHNAME_REGEX")
        config.UAWhitelistRegex = os.Getenv("UA_WHITELIST_REGEX")
        config.UABlacklistRegex = os.Getenv("UA_BLACKLIST_REGEX")
        config.IPWhitelistRegex = os.Getenv("IP_WHITELIST_REGEX")
        config.IPBlacklistRegex = os.Getenv("IP_BLACKLIST_REGEX")
        config.RegionWhitelistRegex = os.Getenv("REGION_WHITELIST_REGEX")
        config.RegionBlacklistRegex = os.Getenv("REGION_BLACKLIST_REGEX")
        config.URL302 = os.Getenv("URL302")
        config.Debug = os.Getenv("DEBUG")
    } else {
        defer file.Close()

        // 从 proxyconfig.json 文件中读取配置
        byteValue, _ := ioutil.ReadAll(file)
        err = json.Unmarshal(byteValue, &config)
        if err != nil {
            log.Fatal("Error parsing proxyconfig.json file:", err)
        }
    }

    return config
}

func logError(r *http.Request, message string) {
    clientIp := r.Header.Get("cf-connecting-ip")
    userAgent := r.Header.Get("user-agent")
    url := r.URL.String()
    log.Printf("%s, clientIp: %s, user-agent: %s, url: %s", message, clientIp, userAgent, url)
}

func createNewRequest(r *http.Request, url string) (*http.Request, error) {
    newRequest, err := http.NewRequest(r.Method, url, r.Body)
    if err != nil {
        return nil, err
    }
    newRequest.Header = r.Header.Clone()  // 只克隆原请求头，不进行任何修改
    return newRequest, nil
}

func setResponseHeaders(originalResponse *http.Response, debug bool) http.Header {
    newResponseHeaders := originalResponse.Header.Clone()  // 只克隆原响应头，不进行任何修改
    if debug {
        newResponseHeaders.Del("content-security-policy")
    }
    return newResponseHeaders
}

func replaceResponseText(originalResponse *http.Response, proxyHostname, pathnameRegex, originHostname string) (string, error) {
    body, err := ioutil.ReadAll(originalResponse.Body)
    if err != nil {
        return "", err
    }
    text := string(body)
    if pathnameRegex != "" {
        pathnameRegex = strings.TrimPrefix(pathnameRegex, "^")
        re := regexp.MustCompile(`\b` + proxyHostname + `\b(` + pathnameRegex + `)`)
        text = re.ReplaceAllString(text, originHostname+"$1")
    } else {
        re := regexp.MustCompile(`\b` + proxyHostname + `\b`)
        text = re.ReplaceAllString(text, originHostname)
    }
    return text, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
    config := loadConfig()
    url := r.URL
    originHostname := url.Hostname()
    proxyHostname := config.ProxyHostname

    // 获取请求头中的IP和地区信息
    clientIP := r.Header.Get("cf-connecting-ip")
    clientRegion := r.Header.Get("cf-ipcountry")

    // 请求验证
    if proxyHostname == "" || 
        (config.PathnameRegex != "" && !regexp.MustCompile(config.PathnameRegex).MatchString(url.Path)) ||
        (config.UAWhitelistRegex != "" && !regexp.MustCompile(config.UAWhitelistRegex).MatchString(strings.ToLower(r.Header.Get("user-agent")))) ||
        (config.UABlacklistRegex != "" && regexp.MustCompile(config.UABlacklistRegex).MatchString(strings.ToLower(r.Header.Get("user-agent")))) ||
        (clientIP != "" && config.IPWhitelistRegex != "" && !regexp.MustCompile(config.IPWhitelistRegex).MatchString(clientIP)) ||
        (clientIP != "" && config.IPBlacklistRegex != "" && regexp.MustCompile(config.IPBlacklistRegex).MatchString(clientIP)) ||
        (clientRegion != "" && config.RegionWhitelistRegex != "" && !regexp.MustCompile(config.RegionWhitelistRegex).MatchString(clientRegion)) ||
        (clientRegion != "" && config.RegionBlacklistRegex != "" && regexp.MustCompile(config.RegionBlacklistRegex).MatchString(clientRegion)) {
        
        logError(r, "Invalid request")
        if config.URL302 != "" {
            http.Redirect(w, r, config.URL302, http.StatusFound)
            return
        }
        w.WriteHeader(http.StatusInternalServerError)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write([]byte(nginx()))
        return
    }
    
    // 只改变 URL 的 Host 和 Scheme，不再替换请求头
    url.Host = proxyHostname
    url.Scheme = config.ProxyProtocol
    newRequest, err := createNewRequest(r, url.String())
    if err != nil {
        logError(r, "Create new request failed")
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    
    originalResponse, err := http.DefaultClient.Do(newRequest)
    if err != nil {
        logError(r, "Fetch error: " + err.Error())
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }
    defer originalResponse.Body.Close()
    
    // 设置响应头，不再替换
    newResponseHeaders := setResponseHeaders(originalResponse, config.Debug == "true")
    for k, v := range newResponseHeaders {
        for _, v2 := range v {
            w.Header().Add(k, v2)
        }
    }

    contentType := newResponseHeaders.Get("content-type")
    var body string
    if strings.Contains(contentType, "text/") {
        body, err = replaceResponseText(originalResponse, proxyHostname, config.PathnameRegex, originHostname)
        if err != nil {
            logError(r, "Replace response text error")
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
    } else {
        bodyBytes, err := ioutil.ReadAll(originalResponse.Body)
        if err != nil {
            logError(r, "Read original response body error")
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        body = string(bodyBytes)
    }

    w.WriteHeader(originalResponse.StatusCode)
    w.Write([]byte(body))
}

func nginx() string {
    return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
}

func main() {
    http.HandleFunc("/", handler)
    log.Fatal(http.ListenAndServe(":5213", nil))
}

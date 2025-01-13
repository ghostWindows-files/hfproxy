package main

import (
    "bufio"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "github.com/joho/godotenv"
)

// 读取 proxyconfig.conf 文件配置
func loadConfig() map[string]string {
    config := make(map[string]string)

    file, err := os.Open("proxyconfig.conf")
    if err != nil {
        log.Println("proxyconfig.conf 文件不存在，尝试加载 .env 文件")
        err = godotenv.Load(".env")
        if err != nil {
            log.Fatal("Error loading .env file")
        }

        config["PROXY_HOSTNAME"] = os.Getenv("PROXY_HOSTNAME")
        config["PROXY_PROTOCOL"] = os.Getenv("PROXY_PROTOCOL")
        config["PATHNAME_REGEX"] = os.Getenv("PATHNAME_REGEX")
        config["UA_WHITELIST_REGEX"] = os.Getenv("UA_WHITELIST_REGEX")
        config["UA_BLACKLIST_REGEX"] = os.Getenv("UA_BLACKLIST_REGEX")
        config["IP_WHITELIST_REGEX"] = os.Getenv("IP_WHITELIST_REGEX")
        config["IP_BLACKLIST_REGEX"] = os.Getenv("IP_BLACKLIST_REGEX")
        config["REGION_WHITELIST_REGEX"] = os.Getenv("REGION_WHITELIST_REGEX")
        config["REGION_BLACKLIST_REGEX"] = os.Getenv("REGION_BLACKLIST_REGEX")
        config["URL302"] = os.Getenv("URL302")
        config["DEBUG"] = os.Getenv("DEBUG")
    } else {
        defer file.Close()

        // 从 proxyconfig.conf 文件中读取配置
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            line := scanner.Text()

            // 检查是否存在多个配置项在同一行
            keyValuePairs := strings.Split(line, ";")
            for _, keyValue := range keyValuePairs {
                if strings.TrimSpace(keyValue) == "" || strings.HasPrefix(keyValue, "#") {
                    continue
                }
                parts := strings.SplitN(keyValue, "=", 2)
                if len(parts) != 2 {
                    continue
                }
                config[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
            }
        }
        if err := scanner.Err(); err != nil {
            log.Fatal(err)
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

func createNewRequest(r *http.Request, url, proxyHostname, originHostname string) (*http.Request, error) {
    newRequest, err := http.NewRequest(r.Method, url, r.Body)
    if err != nil {
        return nil, err
    }
    newRequest.Header = r.Header.Clone()
    for k, v := range newRequest.Header {
        for i := range v {
            newRequest.Header[k][i] = strings.Replace(v[i], originHostname, proxyHostname, -1)
        }
    }
    return newRequest, nil
}

func setResponseHeaders(originalResponse *http.Response, proxyHostname, originHostname string, debug bool) http.Header {
    newResponseHeaders := originalResponse.Header.Clone()
    for k, v := range newResponseHeaders {
        for i := range v {
            newResponseHeaders[k][i] = strings.Replace(v[i], proxyHostname, originHostname, -1)
        }
    }
    if debug {
        newResponseHeaders.Del("content-security-policy")
        // 可以进一步增加其他调试功能
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
    proxyHostname := config["PROXY_HOSTNAME"]

    // 请求验证
    if proxyHostname == "" || 
        !regexp.MustCompile(config["PATHNAME_REGEX"]).MatchString(url.Path) ||
        !regexp.MustCompile(config["UA_WHITELIST_REGEX"]).MatchString(strings.ToLower(r.Header.Get("user-agent"))) ||
        regexp.MustCompile(config["UA_BLACKLIST_REGEX"]).MatchString(strings.ToLower(r.Header.Get("user-agent"))) ||
        !regexp.MustCompile(config["IP_WHITELIST_REGEX"]).MatchString(r.Header.Get("cf-connecting-ip")) ||
        regexp.MustCompile(config["IP_BLACKLIST_REGEX"]).MatchString(r.Header.Get("cf-connecting-ip")) ||
        !regexp.MustCompile(config["REGION_WHITELIST_REGEX"]).MatchString(r.Header.Get("cf-ipcountry")) ||
        regexp.MustCompile(config["REGION_BLACKLIST_REGEX"]).MatchString(r.Header.Get("cf-ipcountry")) {
        
        logError(r, "Invalid request")
        if config["URL302"] != "" {
            http.Redirect(w, r, config["URL302"], http.StatusFound)
            return
        }
        w.WriteHeader(http.StatusInternalServerError)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write([]byte(nginx()))
        return
    }
    url.Host = proxyHostname
    url.Scheme = config["PROXY_PROTOCOL"]
    newRequest, err := createNewRequest(r, url.String(), proxyHostname, originHostname)
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
    newResponseHeaders := setResponseHeaders(originalResponse, proxyHostname, originHostname, config["DEBUG"] == "true")
    for k, v := range newResponseHeaders {
        for _, v2 := range v {
            w.Header().Add(k, v2)
        }
    }
    contentType := newResponseHeaders.Get("content-type")
    var body string
    if strings.Contains(contentType, "text/") {
        body, err = replaceResponseText(originalResponse, proxyHostname, config["PATHNAME_REGEX"], originHostname)
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

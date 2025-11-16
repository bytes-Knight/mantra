package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
	thread         *int
	silent         *bool
	ua             *string
	rc             *string
	detailed       *bool
	secrets        map[string]bool = make(map[string]bool)
	extrapattern   *string
	secretsPatterns []*regexp.Regexp
)

func init() {
	// Initialize flags
	silent = flag.Bool("s", false, "silent")
	thread = flag.Int("t", 50, "thread number")
	ua = flag.String("ua", "Mantra", "User-Agent")
	detailed = flag.Bool("d", false, "detailed")
	rc = flag.String("c", "", "cookies")
	extrapattern = flag.String("ep", "", "extra, custom (regexp) pattern")
}

func compilePatterns() {
	var secretsPatternsStrings = []string{`COGNITO_IDENTITY[A-Z0-9_]*:\s*"[^"]+"`, `(?P<key>CANDEX_[A-Z_]+):\s*"(?P<value>[^"]+)"`, `REACT_APP_[A-Z_]+:\s*"([^"]+)"`, `com\.amplify\.Cognito\.[a-z0-9-]+\.([a-zA-Z0-9]+)\.identityId`, `Basic [A-Za-z0-9+/]{15}`, "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})", "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]", "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]", "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "key-[0-9a-zA-Z]{32}", "[0-9a-f]{32}-us[0-9]{1,2}", "sk_live_[0-9a-z]{32}", "[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com", "AIza[0-9A-Za-z-_]{35}", "6L[0-9A-Za-z-_]{38}", "ya29\\.[0-9A-Za-z\\-_]+", "AKIA[0-9A-Z]{16}", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com", "EAACEdEose0cBA[0-9A-Za-z]+", "key-[0-9a-zA-Z]{32}", "SK[0-9a-fA-F]{32}", "AC[a-zA-Z0-9_\\-]{32}", "AP[a-zA-Z0-9_\\-]{32}", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", "sq0csp-[ 0-9A-Za-z\\-_]{43}", "sqOatp-[0-9A-Za-z\\-_]{22}", "sk_live_[0-9a-zA-Z]{24}", "rk_live_[0-9a-zA-Z]{24}", "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*", "-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----"}
	if len(*extrapattern) > 0 {
		secretsPatternsStrings = append(secretsPatternsStrings, *extrapattern)
	}

	for _, pattern := range secretsPatternsStrings {
		re, err := regexp.Compile(pattern)
		if err == nil {
			secretsPatterns = append(secretsPatterns, re)
		}
	}
}

func req(url string) {
	if !strings.Contains(url, "http") {
		fmt.Println("\033[31m[-]\033[37m Send URLs via stdin (ex: cat js.txt | mantra). Each url must contain 'http' string.")
		os.Exit(0)
	}

	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()

	transp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpclient := &http.Client{Transport: transp}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Cookie", *rc)

	if *detailed {
		fmt.Println("\033[33m[*]\033[37m", "\033[37m"+"Processing URL: "+url+"\033[37m")
	}

	r, err := httpclient.Do(req)
	if err != nil {
		fmt.Println("\033[31m[-]\033[37m", "\033[37m"+"Unable to make a request for "+url+"\033[37m")
		return
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println("\033[31m[-]\033[37m", "\033[37m"+"Unable to read the body of "+url+"\033[37m")
		return
	}
	strbody := string(body)

	for _, secretPattern := range secretsPatterns {
		if secretPattern.MatchString(strbody) {
			secret := secretPattern.FindString(strbody)
			if secrets[secret] {
				continue
			}
			secrets[secret] = true

			if *detailed {
				lines := strings.Split(strbody, "\n")
				for i, line := range lines {
					if strings.Contains(line, secret) {
						fmt.Printf("\033[32m[+]\033[37m %s \033[32m[\033[37m%s\033[32m] [\033[37mLine: %d\033[32m]\033[37m\n", url, secret, i+1)
					}
				}
			} else {
				if secret != *extrapattern {
					fmt.Printf("\033[1;32m[+]\033[37m %s \033[1;32m[\033[37m%s\033[1;32m]\033[37m\n", url, secret)
				} else {
					fmt.Printf("\033[32m[+]\033[37m %s \033[32m[\033[37m%s\033[32m] -- Extra pattern detected! --\033[0m\n", url, secret)
				}
			}
		}
	}
}

func banner() {
	fmt.Printf("\033[31m" + `
	███╗   ███╗ █████╗ ███╗   ██╗████████╗██████╗  █████╗ 
	████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗
	██╔████╔██║███████║██╔██╗ ██║   ██║   ██████╔╝███████║
	██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██╔══██╗██╔══██║
	██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║  ██║██║  ██║
	╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
			   ` + "\033[31m[\033[37mCoded by Brosck\033[31m]\n" +
		`                             ` + "\033[31m[\033[37mVersion 3.2\033[31m]\n")
}

func main() {
	flag.Parse()

	if !*silent {
		banner()
	}

	compilePatterns()

	stdin := bufio.NewScanner(os.Stdin)
	urls := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				req(url)
			}
		}()
	}

	for stdin.Scan() {
		urls <- stdin.Text()
	}

	close(urls)
	wg.Wait()
}

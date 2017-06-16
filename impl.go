package http_authproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/linuzilla/ipacl"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"
)

type proxyHandler struct {
	conf        Config
	password    string
	proxyAcl    ipacl.IPListMgmt
	acl         ipacl.IPListMgmt
	proxyHeader string
	ipregexp    *regexp.Regexp
}

func (self *proxyHandler) doProxy(w http.ResponseWriter, r *http.Request, fp *os.File) {
	var client = &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	urlstr := self.conf.Scheme + "://" + self.conf.Host + r.RequestURI

	fmt.Fprintln(fp, r.Method, urlstr)
	requestBody, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	fp.Write(requestBody)

	bodyReader := bytes.NewReader(requestBody)

	if req, err := http.NewRequest(r.Method, urlstr, bodyReader); err != nil {
		log.Fatal(err)
	} else {
		for k, v := range r.Header {
			for _, vv := range v {
				req.Header.Add(k, vv)
			}
		}

		if response, err := client.Do(req); err != nil {
			fmt.Println(err)
			fmt.Fprintln(fp, "\n-----------------\n", err)
		} else {
			defer response.Body.Close()

			if body, err := ioutil.ReadAll(response.Body); err != nil {
				fmt.Println(err)
			} else {
				fmt.Fprintln(fp, "\n-------------------------------------")
				fp.Write(body)
				w.Write(body)
			}
		}
	}
}

func (self *proxyHandler) isAcceptable(user, passwd, remoteip string) bool {
	if val, found := self.conf.AcceptableFrom[user]; found {
		if val.Password != passwd {
			return false
		} else {
			return val.acl.Contains(remoteip)
		}
	}
	return false
}

func (self *proxyHandler) createLogfile(remoteIp string) (*os.File, error) {
	now := time.Now()

	logbase := fmt.Sprintf("%s/%s", self.conf.LogDir, remoteIp)
	if _, err := os.Stat(logbase); os.IsNotExist(err) {
		os.Mkdir(logbase, 0755)
	}

	logdir := fmt.Sprintf("%s/%4d-%02d", logbase, now.Year(), now.Month())
	if _, err := os.Stat(logdir); os.IsNotExist(err) {
		os.Mkdir(logdir, 0755)
	}

	logfile := fmt.Sprintf("%s/%02d-%02d%02d%02d", logdir, now.Day(), now.Hour(), now.Minute(), now.Second())

	var lastError error
	for i := 0; i < 5; i++ {
		fp, err := os.OpenFile(logfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			logfile = fmt.Sprintf("%s/%02d-%02d%02d%02d-%d",
				logdir, now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond())
			lastError = err
		} else {
			return fp, nil
		}
	}
	return nil, lastError
}

func (self *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIp := r.RemoteAddr

	if m := self.ipregexp.FindStringSubmatch(remoteIp); m != nil {
		remoteIp = m[1]
	}

	if self.proxyAcl != nil && self.proxyAcl.Contains(remoteIp) {
		if rip := r.Header.Get(self.proxyHeader); rip != "" {
			remoteIp = rip
		}
	}

	if self.acl.Contains(remoteIp) {
		if fp, err := self.createLogfile(remoteIp); err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 - Something bad happened!"))
		} else {
			defer fp.Close()

			fmt.Println(r.RequestURI)

			if user, passwd, ok := r.BasicAuth(); ok {
				if self.isAcceptable(user, passwd, remoteIp) {
					r.Header.Del(`Authorization`)
					r.SetBasicAuth(self.conf.ProxyAccount.Username, self.conf.ProxyAccount.Password)
					fmt.Fprintln(fp, "BasicAuth: ", user)
				} else {
					fmt.Fprintln(fp, "BasicAuth (passthru): ", user, '/', passwd)
				}
			} else {
				fmt.Fprintln(fp, "BasicAuth: none")
			}

			self.doProxy(w, r, fp)
		}
	} else {
		fmt.Fprint(w, `The quieter you become, the more you are able to hear.`)
		fmt.Println(r.RequestURI, "[ deny from:", remoteIp, "]")
	}
}

func New(conf *Config) http.Handler {
	self := &proxyHandler{conf: *conf}

	if data, err := base64.StdEncoding.DecodeString(self.conf.ProxyAccount.Base64pass); err != nil {
		log.Fatal(err)
	} else {
		self.conf.ProxyAccount.Password = string(data)
	}

	for _, entry := range self.conf.AcceptableFrom {
		if data, err := base64.StdEncoding.DecodeString(entry.Base64pass); err != nil {
			log.Fatal(err)
		} else {
			entry.Password = string(data)
			entry.acl = ipacl.New()
		}
	}

	self.acl = ipacl.New()

	for _, entry := range self.conf.AcceptableFrom {
		for _, ipentry := range entry.AccessList {
			if err := self.acl.AddEntry(ipentry); err != nil {
				log.Fatal(err)
			}
			entry.acl.AddEntry(ipentry)
		}
	}

	if tag := self.conf.TrustyHeader; tag != "" {
		if proxyIP := self.conf.TrustyProxy; proxyIP != "" {
			acl := ipacl.New()
			if err := acl.AddEntry(proxyIP); err != nil {
				log.Fatal(err)
			} else {
				self.proxyAcl = acl
				self.proxyHeader = tag
			}
		}
	}

	self.ipregexp = regexp.MustCompile(`^(.*):\d+$`)

	return self
}

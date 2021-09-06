package ipline

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/lionsoul2014/ip2region/binding/golang/ip2region"
	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"gorm.io/gorm"
	"net"
	"strings"
	"sync"
)

var privateIPBlocks []*net.IPNet

func init() {
	fmt.Println("init ipline")

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}

	middleware.Register("ipline", func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

const languageCN = "CN"

const (
	IPLineDefault = "默认"
	IPLineMbi     = "移动"
	IPLineUni     = "联通"
	IPLineTele    = "电信"
	IPLineForg    = "海外"
	IPLineEdu     = "教育网"
)

type ModelDomain struct {
	*gorm.Model
	Name string `gorm:"unique"`
}

type IPLine struct {
	logger        log.Logger
	authAddr      string
	dnspowerRedis *redis.Client
	ip2Region     *ip2region.Ip2Region
	rw            sync.RWMutex
	digSvc        *dnsutil.Dig
	ctx           context.Context
}

func (ipline *IPLine) checkDomainExisted(domain string) (string, bool) {
	domain = MakeDomainCanonical(domain)
	res, err := ipline.dnspowerRedis.Exists(ipline.ctx, domain).Result()
	if err != nil && err != redis.Nil {
		ipline.logger.Error(fmt.Errorf("query whether %v existed in redis failed:%w", domain, err).Error())
		return "", false
	}

	if res == 1 {
		return domain, true
	}

	elems := strings.Split(domain, ".")
	checkKey := MakeDomainCanonical(domain)
	if len(elems) == 3 {
		checkKey = fmt.Sprintf("@.%v.", domain)
	} else if len(elems) == 4 {
		checkKey = fmt.Sprintf("*.%v.%v.", elems[1], elems[2])
	}
	res, err = ipline.dnspowerRedis.Exists(ipline.ctx, checkKey).Result()
	if err != nil && err != redis.Nil {
		ipline.logger.Error(fmt.Sprintf("query whether %v existed in redis failed", checkKey))
		return "", false
	}
	return checkKey, res == 1
}

func (ipline *IPLine) GetLineSettingFromRedis(domain, ip string) string {
	domain = MakeDomainCanonical(domain)
	ipline.logger.Info(fmt.Sprintf("domain:%v, ip:%v", domain, ip))
	res, err := ipline.dnspowerRedis.HGet(ipline.ctx, domain, ip).Result()
	if err != nil {
		ipline.logger.Error(fmt.Errorf("hget ip line failed:%w", err).Error())
		return ""
	}
	return res
}

func (ipline *IPLine) resolveDomain(domain string) ([]*dns.A, error) {
	a, err := ipline.digSvc.A(domain)
	if err != nil {
		return nil, fmt.Errorf("dig A record failed:%w", err)
	}
	return a, err
}

func (ipline *IPLine) QueryIPISP(ip string) (string, error) {
	if ip == "127.0.0.1" {
		return IPLineDefault, nil
	}
	region, err := ipline.ip2Region.BtreeSearch(ip)
	if err != nil {
		return "", err
	}
	country := region.Country
	province := region.Province
	isp := region.ISP
	if !strings.Contains(country, "中国") {
		return IPLineForg, nil
	}
	if strings.Contains(province, "香港") || strings.Contains(province, "澳门") || strings.Contains(province, "台湾") {
		return IPLineForg, nil
	}
	if strings.Contains(isp, IPLineTele) {
		return IPLineTele, nil
	}
	if strings.Contains(isp, IPLineUni) {
		return IPLineUni, nil
	}
	if strings.Contains(isp, IPLineMbi) {
		return IPLineMbi, nil
	}
	if strings.Contains(isp, IPLineEdu) {
		return IPLineEdu, nil
	}
	return "", fmt.Errorf("unknown isp info:%v", isp)
}

func New(conf *config.Config) middleware.Handler {
	logger := log.New("middleware", "ipline")
	logger.Info("new ipline...")

	digSvc := new(dnsutil.Dig)
	logger.Info(fmt.Sprintf("dnsbaackend:%v", conf.DnspowerBackendAddr))
	if err := digSvc.At(conf.DnspowerBackendAddr); err != nil {
		panic(fmt.Errorf("at dig svc failed:%w", err))
	}

	redisDB := redis.NewClient(&redis.Options{
		Addr:     conf.DnspowerBackendRedisAddr,
		Password: conf.DnspowerBackendRedisPass,
	})

	if err := redisDB.Ping(context.Background()).Err(); err != nil {
		panic(fmt.Errorf("ping dns backend redis failed:%w", err))
	}

	ip2Region, err := ip2region.New(conf.IpDataPath)
	if err != nil {
		panic(fmt.Errorf("open ip data path failed:%w", err))
	}

	ipline := &IPLine{
		logger:        logger,
		authAddr:      conf.DnspowerBackendAddr,
		ip2Region:     ip2Region,
		digSvc:        digSvc,
		ctx:           context.Background(),
		dnspowerRedis: redisDB,
	}
	logger.Info("new ipline succeed")
	return ipline
}

func (ipline *IPLine) Name() string {
	return "ipline"
}

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ips []*dns.A) []dns.RR {
	answers := []dns.RR{}
	for _, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: ip.Hdr.Ttl}
		r.A = ip.A
		answers = append(answers, r)
	}
	return answers
}

func cname(zone string, vals []*dns.CNAME) []dns.RR {
	ans := []dns.RR{}
	for _, val := range vals {
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{
			Name: zone, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: val.Hdr.Ttl}
		r.Target = val.Target
		ans = append(ans, r)
	}
	return ans
}

func (ipline *IPLine) isSupportLineMode(tp uint16) bool {
	return tp == dns.TypeA
}

func isPrivateIP(rawIP string) bool {
	ip := net.ParseIP(rawIP)
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}


func (ipline *IPLine) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req, wtr := ch.Request, ch.Writer

	qs := req.Question[0]

	if isPrivateIP(wtr.RemoteIP().String()) {
		ch.Next(ctx)
		return
	}

	checkKey, existed := ipline.checkDomainExisted(qs.Name)
	if !existed {
		ch.CancelWithRcode(dns.RcodeRefused, false)
		return
	}

	if qs.Qtype == dns.TypeA {
		incomeip := wtr.RemoteIP().String()
		incomeLine, err := ipline.QueryIPISP(incomeip)
		if err != nil {
			ipline.logger.Error(fmt.Errorf("query ip %v line failed:%w", incomeip, err).Error())
			ch.CancelWithRcode(dns.RcodeServerFailure, false)
			return
		}

		pdnsMsg := dnsutil.NewMsg(dns.TypeA, qs.Name)
		pdnsRsp, err := ipline.digSvc.Exchange(pdnsMsg)
		if err != nil {
			ipline.logger.Error(fmt.Errorf("exchage dns msg with domain %v failed:%w", qs.Name, err).Error())
			ch.CancelWithRcode(dns.RcodeNameError, false)
			return
		}

		defaultRetRR := make([]dns.RR, 0, 5)
		rrListRet := make([]dns.RR, 0, 10)
		lineMatched := false

		for _, ans := range pdnsRsp.Answer {
			var val string
			switch ans.Header().Rrtype {
			case dns.TypeA:
				val = ans.(*dns.A).A.String()
			case dns.TypeCNAME:
				val = ans.(*dns.CNAME).Target
			case dns.TypeNS:
				val = ans.(*dns.NS).Ns
			case dns.TypeTXT:
				val = ans.(*dns.TXT).Txt[0]
			}
			recordLine := ipline.GetLineSettingFromRedis(checkKey, val)
			ipline.logger.Info(fmt.Sprintf("iter pdns ans...type:%v val:%v line:%v", ans.Header().Rrtype, val, recordLine))
			if recordLine == "" {
				ipline.logger.Error(fmt.Errorf("can't get record line from redis failed").Error())
				ch.CancelWithRcode(dns.RcodeServerFailure, false)
				return
			}
			if recordLine == IPLineDefault {
				defaultRetRR = append(defaultRetRR, ans)
			}
			if recordLine == incomeLine {
				lineMatched = true
				rrListRet = append(rrListRet, ans)
			}
		}
		if !lineMatched && len(rrListRet) == 0 {
			rrListRet = append(rrListRet, defaultRetRR...)
		}
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative, msg.RecursionAvailable = true, true
		msg.Answer = rrListRet
		if err := wtr.WriteMsg(msg); err != nil {
			ipline.logger.Error(err.Error())
		}
		ch.Cancel()
	} else if qs.Qtype == dns.TypeNS {
		msg := dnsutil.NewMsg(dns.TypeNS, qs.Name)
		rsp, err := ipline.digSvc.Exchange(msg)
		if err != nil {
			ipline.logger.Error(fmt.Errorf("exchage ns msg with domain %v failed:%w", qs.Name, err).Error())
			ch.CancelWithRcode(dns.RcodeNameError, false)
			return
		}
		rsp.SetReply(req)
		if err := wtr.WriteMsg(rsp); err != nil {
			ipline.logger.Error(err.Error())
		}
		ch.Cancel()
	} else {
		ch.Next(ctx)
	}
}

func MakeDomainCanonical(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return fmt.Sprintf("%s.", name)
}

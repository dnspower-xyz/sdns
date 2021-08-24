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
	"strings"
	"sync"
)

func init() {
	fmt.Println("init ipline")
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

func (ipline *IPLine) checkDomainExisted(domain string) bool {
	domain = MakeDomainCanonical(domain)
	res, err := ipline.dnspowerRedis.Exists(ipline.ctx, domain).Result()
	if err != nil {
		ipline.logger.Error("query domain existed in redis failed", err)
		return false
	}
	return res == 1
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
	return tp == dns.TypeA || tp == dns.TypeCNAME
}

func (ipline *IPLine) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req, wtr := ch.Request, ch.Writer

	qs := req.Question[0]
	ipline.logger.Info(fmt.Sprintf("qs.name: %v", qs.Name))

	fmt.Println("existed:", ipline.checkDomainExisted(qs.Name), qs.Qtype)
	if ipline.isSupportLineMode(qs.Qtype) && ipline.checkDomainExisted(qs.Name) {
		incomeIP := wtr.RemoteIP().String()
		incomeISP, err := ipline.QueryIPISP(incomeIP)
		if err != nil {
			ipline.logger.Error(fmt.Errorf("query ip %v isp failed:%w", incomeIP, err).Error())
		}

		rrListQuery := make([]dns.RR, 0, 10)
		rrListRet := make([]dns.RR, 0, 10)

		switch qs.Qtype {
		case dns.TypeA:
			aList, err := ipline.digSvc.A(qs.Name)
			if err != nil {
				ipline.logger.Error(fmt.Errorf("dig cname %v failed:%w", qs.Name, err).Error())
				return
			}
			for _, a := range aList {
				rrListQuery = append(rrListQuery, a)
			}
		case dns.TypeCNAME:
			cList, err := ipline.digSvc.CNAME(qs.Name)
			if err != nil {
				ipline.logger.Error(fmt.Errorf("dig cname %v failed:%w", qs.Name, err).Error())
				return
			}
			for _, c := range cList {
				rrListQuery = append(rrListQuery, c)
			}
		default:
			ipline.logger.Error(fmt.Errorf("unsupported dns type %v", qs.Qtype).Error())
		}

		defaultRetRR := make([]dns.RR, 0, 5)
		lineMatched := false

		for _, r := range rrListQuery {
		    var recordLine string
		    var val string
			switch r.(type) {
			case *dns.A:
				val = r.(*dns.A).A.String()
				recordLine = ipline.GetLineSettingFromRedis(qs.Name, val)
			case *dns.CNAME:
				val = r.(*dns.CNAME).Target
				recordLine = ipline.GetLineSettingFromRedis(qs.Name, val)
			}
			if recordLine == "" {
				ipline.logger.Error(fmt.Sprintf("can't get line if of record val %v from redis", val))
				continue
			}
			ipline.logger.Info(fmt.Sprintf("record val %v(%v), income ip %v(%v)",
				val, recordLine, incomeIP, incomeISP))
			if recordLine == IPLineDefault {
				defaultRetRR = append(defaultRetRR, r)
			}
			if recordLine == incomeISP {
				lineMatched = true
				rrListRet = append(rrListRet, r)
			}
		}

		if !lineMatched && len(rrListRet) == 0 {
			rrListRet = append(rrListRet, defaultRetRR...)
			ipline.logger.Info(fmt.Sprintf("%s unmatched any line setting, return %v default ips",
				qs.Name, len(defaultRetRR)))
		}
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative, msg.RecursionAvailable = true, true
		msg.Answer = rrListRet
		if err := wtr.WriteMsg(msg); err != nil {
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

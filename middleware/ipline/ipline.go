package ipline

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/ipipdotnet/ipdb-go"
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

func init() {
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
)

type ModelDomain struct {
	*gorm.Model
	Name string `gorm:"unique"`
}

type IPLine struct {
	logger        log.Logger
	authAddr      string
	dnspowerRedis *redis.Client
	ipData        *ipdb.City
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

func (ipline *IPLine) getLineSetting(domain, ip string) string {
	domain = MakeDomainCanonical(domain)
	ipline.logger.Info(fmt.Sprintf("domain:%v, ip:%v", domain, ip))
	res,err := ipline.dnspowerRedis.HGet(ipline.ctx, domain, ip).Result()
	if err != nil {
		ipline.logger.Error(fmt.Errorf("hget ip line failed:%w", err).Error())
		return ""
	}
	return res
}

func (ipline *IPLine) resolveDomain(domain string) ([]string, error) {
	a, err := ipline.digSvc.A(domain)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(a))
	for _, ip := range a {
		ips = append(ips, ip.A.String())
	}
	return ips, nil
}

func (ipline *IPLine) IPIspDomain(ip string) string {
	info, err := ipline.ipData.FindInfo(ip, languageCN)
	if err != nil {
		ipline.logger.Error("find ip info failed", err)
		return ""
	}
	return info.IspDomain
}

func (ipline *IPLine) IsChinaIP(ip string) bool {
	info, err := ipline.ipData.FindInfo(ip, languageCN)
	if err != nil {
		ipline.logger.Error("find ip info failed", err)
		return false
	}
	return info.CountryName == "中国"
}

func New(conf *config.Config) middleware.Handler {
	logger := log.New("middleware", "ipline")
	logger.Info("new ipline...")

	ipData, err := ipdb.NewCity(conf.IpDataPath)
	if err != nil {
		panic(fmt.Errorf("open ipdb %v failed:%w",conf.IpDataPath, err))
	}

	digSvc := new(dnsutil.Dig)
	if err := digSvc.At(conf.DnspowerBackendAddr);err != nil {
		panic(fmt.Errorf("at dig svc failed:%w", err))
	}

	redisDB := redis.NewClient(&redis.Options{
		Addr: conf.DnspowerBackendRedisAddr,
	})

	ipline := &IPLine{
		logger:   logger,
		authAddr: conf.DnspowerBackendAddr,
		ipData:   ipData,
		digSvc:   new(dnsutil.Dig),
		ctx:      context.Background(),
		dnspowerRedis: redisDB,
	}
	logger.Info("new ipline succeed")
	return ipline
}

func (ipline *IPLine) Name() string {
	return "ipline"
}

func (ipline *IPLine) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req, wtr := ch.Request, ch.Writer

	qs := req.Question[0]
	ipline.logger.Info("qs.name", qs.Name)

	if qs.Qtype == dns.TypeA && ipline.checkDomainExisted(qs.Name) {
	    incomeIP := ch.Writer.RemoteIP().String()
	    incomeIsp := ipline.IPIspDomain(incomeIP)

		ips, err := ipline.resolveDomain(qs.Name)
		if err != nil {
			ipline.logger.Error("resolve domain failed", err)
			return
		}

		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Authoritative, msg.RecursionAvailable = true, false

		header := dns.RR_Header{
			Name: qs.Name,
			Rrtype: dns.TypeA,
			Class: dns.ClassINET,
		}

		retIPs := make([]string, 0, len(ips))
		for _, ip := range ips {
		    ansIPIsp := ipline.getLineSetting(qs.Name, ip)
		    if ansIPIsp == IPLineDefault {
		    	retIPs = append(retIPs, ip)
			} else if ansIPIsp == incomeIsp {
				retIPs = append(retIPs, ip)
			}
			msg.Answer = append(msg.Answer, &dns.A{Hdr: header, A: net.IP(ip)})
		}

		_ = wtr.WriteMsg(msg)

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

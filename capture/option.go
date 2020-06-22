package capture

import (
	"log"
	"strconv"
	"time"
)

type OptionFunc func(*Option)

type Option struct {
	CaptureAddr     string //采集地址
	Port            string //采集端口
	BpfFilter       string //过滤器
	TimestampType   string //时间格式类型
	OverrideSnapLen bool
	SnapLen         int  //default 65536
	ImmediateMode   bool //模式类型
	TrackResponse   bool
	BufferSize      int //缓冲区大小
	MessageExpire   time.Duration
	TimeOutExpire   time.Duration //响应的超时时间 60s默认
	Promisc         bool
}

func (o *Option) GetPort() uint16 {
	p, err := strconv.Atoi(o.Port)
	if err != nil {
		log.Println("GetPort Atoi err->", err)
	}
	return uint16(p)
}

func Opt2ActiveOpt(opt *Option) *activeOpt {
	actopt := &activeOpt{
		TimestampType: opt.TimestampType,
		SnapLen:       opt.SnapLen,
		TimeOutExpire: opt.MessageExpire,
		Promisc:       opt.Promisc,
		ImmediateMode: opt.ImmediateMode,
		BufferSize:    opt.BufferSize,
	}
	return actopt
}

func NewOption(opts ...OptionFunc) *Option {
	opt := &Option{
		CaptureAddr:     "0.0.0.0",
		Port:            "8080",
		BpfFilter:       "",
		TimestampType:   "",
		OverrideSnapLen: false,
		SnapLen:         65536,
		ImmediateMode:   false,
		TrackResponse:   true,
		BufferSize:      10 * 1024 * 1024, //10kB
		MessageExpire:   3 * time.Second,  //3秒时间
		Promisc:         false,
		TimeOutExpire:   60 * time.Second,
	}

	for _, o := range opts {
		o(opt)
	}
	return opt
}

//这个是一个案例如何使用NewOption 这个进行初始化
func NewDefaultOption() *Option {
	return NewOption(
		OptCaptureAddr("172.31.122.174"),
		OptPort("12800"),
	)
}

func OptCaptureAddr(addr string) OptionFunc {
	return func(o *Option) {
		o.CaptureAddr = addr
	}
}
func OptPort(port string) OptionFunc {
	return func(o *Option) {
		o.Port = port
	}
}
func OptSnapLen(snaplen int) OptionFunc {
	return func(o *Option) {
		o.SnapLen = snaplen
	}
}
func OptBpfFilter(BpfFilter string) OptionFunc {
	return func(o *Option) {
		o.BpfFilter = BpfFilter
	}
}
func OptTrackResponse(track bool) OptionFunc {
	return func(o *Option) {
		o.TrackResponse = track
	}
}

func OptMessageExpire(expire time.Duration) OptionFunc {
	return func(o *Option) {
		if expire == 0*time.Second {
			o.MessageExpire = time.Second * 3
		} else {
			o.MessageExpire = expire
		}

	}
}

func OptPromisc(promisc bool) OptionFunc {
	return func(o *Option) {
		o.Promisc = promisc
	}
}

func OptTimestampType(timetype string) OptionFunc {
	return func(o *Option) {
		o.TimestampType = timetype
	}
}

func OptTimeOut(expire time.Duration) OptionFunc {
	return func(o *Option) {
		if expire < 5*time.Second {
			o.TimeOutExpire = time.Second * 60
		} else {
			o.TimeOutExpire = expire
		}

	}
}

package capture

import (
	"errors"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type activeOpt struct {
	TimestampType string
	SnapLen       int
	TimeOutExpire time.Duration
	Promisc       bool
	ImmediateMode bool
	BufferSize    int
}

func NewPcapInactive(device pcap.Interface, opt *activeOpt) (*pcap.InactiveHandle, error) {
	inactive, err := pcap.NewInactiveHandle(device.Name)
	if err != nil {
		return nil, err
	}
	//进行相关设置
	if opt.TimestampType != "" {
		if tt, terr := pcap.TimestampSourceFromString(opt.TimestampType); terr != nil {
			log.Println("Supported timestamp types: ", inactive.SupportedTimestamps(), device.Name)
		} else if terr := inactive.SetTimestampSource(tt); terr != nil {
			log.Println("Supported timestamp types: ", inactive.SupportedTimestamps(), device.Name)
		}
	}

	//设置采集包缓存大小 采集包的不能过小
	it, err := net.InterfaceByName(device.Name)
	if err == nil && opt.SnapLen > 0 && opt.SnapLen < it.MTU {
		inactive.SetSnapLen(it.MTU + 68*2)
	} else {
		inactive.SetSnapLen(65536)
	}

	//设置超时时间
	inactive.SetTimeout(opt.TimeOutExpire)
	//设置混杂模式
	inactive.SetPromisc(opt.Promisc)
	inactive.SetImmediateMode(opt.ImmediateMode)
	//log.Println(device.Name+" SetImmediateMode ->", opt.ImmediateMode)
	//log.Println(device.Name+" SetBufferSize ->", opt.BufferSize)
	if opt.BufferSize > 0 {
		inactive.SetBufferSize(opt.BufferSize)
	}
	return inactive, nil
}

func ListenAllInterfaces(addr string) bool {
	switch addr {
	case "", "0.0.0.0", "[::]", "::":
		return true
	default:
		return false
	}
}

func IsLoopback(device pcap.Interface) bool {
	if len(device.Addresses) == 0 {
		return false
	}
	switch device.Addresses[0].IP.String() {
	case "127.0.0.1", "::1":
		return true
	}
	return false
}

func FindPcapDevices(addr string) (interfaces []pcap.Interface, err error) {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln("FindAllDevs Err->", err, " Addr->", addr)
		return
	}

	if len(devices) == 0 {
		return nil, errors.New("Can't get list of network interfaces, ensure that you running Gor as root user or sudo.")
	}

	allInterfaces := ListenAllInterfaces(addr)
	for _, device := range devices {
		if (allInterfaces && len(device.Addresses) > 0) || IsLoopback(device) {
			interfaces = append(interfaces, device)
			continue
		}

		if device.Name == addr {
			interfaces = append(interfaces, device)
			return
		}

		for _, address := range device.Addresses {
			if address.IP.String() == addr {
				interfaces = append(interfaces, device)
				return
			}
		}
	}
	if len(interfaces) == 0 {
		return nil, errors.New("Can't find interfaces with addr: " + addr + ". Provide available IP for intercepting traffic")
	}
	return interfaces, nil
}

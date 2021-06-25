package main


/*
int get_pid()
{
	return getpid();
}
*/
import "C"

import (
	// "encoding/hex"
	"fmt"
	"log"
	"net"
	"os"

	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var wg sync.WaitGroup

//错误处理
func printError(err error) {
	if err != nil {
		log.Println(err)
		//os.Exit(1)
	}
}

//获得本地ip和可用端口
func getLocalIpport(dstip net.IP) (ip net.IP, port int, err error) {
	serveraddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	printError(err)
	conn, err := net.DialUDP("udp", nil, serveraddr)
	printError(err)
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP, addr.Port, nil
	}
	return nil, -1, err
}

//全连接扫描
func FullScan(dstip string, dstport int) bool {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", dstip, dstport)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		//fmt.Printf("%s 关闭了\n", address)
		return false
	}
	conn.Close()
	log.Printf("%s 打开了\n", address)
	return true
}

//SYN扫描
func SynScan(dstip string, dstport int) bool {

	defer wg.Done()
	// log.Println(dstip, dstport)

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	printError(err)

	dstaddr := net.ParseIP(dstip)
	printError(err)

	srcip, srcport, err := getLocalIpport(net.ParseIP(dstip))
	printError(err)

	// log.Println(srcip, srcport, dstaddr, dstport)

	ip := &layers.IPv4{
		SrcIP:    srcip.To4(),
		DstIP:    net.IP(dstaddr).To4(),
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcport),
		DstPort: layers.TCPPort(dstport),
		SYN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(ip)
	printError(err)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, tcp)
	printError(err)

	defer conn.Close()

	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstaddr})
	printError(err)

	err = conn.SetDeadline(time.Now().Add(4 * time.Second))
	printError(err)

	for {
		recbuf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(recbuf)
		//printError(err)
		if err != nil {
			return false
		} else if addr.String() == dstip {
			packet := gopacket.NewPacket(recbuf[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
				tcp, _ := tcplayer.(*layers.TCP)
				// fmt.Println("src", srcport, "dst", dstport, "dstport", tcp.DstPort, "srcport", tcp.SrcPort, tcp.Seq)
				if tcp.DstPort == layers.TCPPort(srcport) {
					if tcp.SYN && tcp.ACK {
						log.Printf("%v:%d is open\n", dstip, dstport)
						return true
					} else {
						return false
					}
				}
			}
		}
	}

	//return false
}

type portMap struct {
	srcport, dstport int
}

var m map[portMap]int = make(map[portMap]int)
var ps map[int]bool = make(map[int]bool)
var handle *pcap.Handle
var lock sync.Mutex
var err error

func Listen() {
	defer wg.Done()

	var (
		device       string        = "ens33"
		snapshot_len int32         = 1024
		promiscuous  bool          = false
		timeout      time.Duration = 4 * time.Second
	)
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		iplayer := packet.Layer(layers.LayerTypeIPv4)
		if iplayer != nil {
			ip, _ := iplayer.(*layers.IPv4)
			// fmt.Println(ip.SrcIP)
			if ip.SrcIP.String() == os.Args[2] {
				tcplayer := packet.Layer(layers.LayerTypeTCP)
				tcp, _ := tcplayer.(*layers.TCP)
				if tcp.RST {
					// fmt.Println(tcp.DstPort, tcp.SrcPort)

					// fmt.Println(tcp.SrcPort)
					lock.Lock()
					if m[portMap{int(tcp.DstPort), int(tcp.SrcPort)}] == 1 {
						m[portMap{int(tcp.DstPort), int(tcp.SrcPort)}] = 2
						ps[int(tcp.SrcPort)] = true
					}
					lock.Unlock()
				}

			}
		}

	}
}

//FIN扫描
func FinScan(dstip string, dstport int) bool {

	// fmt.Println("finscan")
	defer wg.Done()
	// log.Println(dstip, dstport)

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	printError(err)

	dstaddr := net.ParseIP(dstip)
	printError(err)

	srcip, srcport, err := getLocalIpport(net.ParseIP(dstip))
	printError(err)

	// log.Println(srcip, srcport, dstaddr, dstport)

	ip := &layers.IPv4{
		SrcIP:    srcip.To4(),
		DstIP:    net.IP(dstaddr).To4(),
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcport),
		DstPort: layers.TCPPort(dstport),
		FIN:     true,
	}

	err = tcp.SetNetworkLayerForChecksum(ip)
	printError(err)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, tcp)
	printError(err)

	defer conn.Close()

	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstaddr})
	printError(err)
	// fmt.Println(n, "write over")

	lock.Lock()
	m[portMap{srcport: srcport, dstport: dstport}] = 1
	lock.Unlock()
	return false
}

func IcmpScan(dstip string, count int) bool {
	defer wg.Done()
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	printError(err)
	dstaddr := net.ParseIP(dstip)
	printError(err)
	pid := uint16(C.get_pid())

	for i := 1; i <= count; i++ {
		icpm := &layers.ICMPv4{
			Seq:      uint16(i),
			TypeCode: layers.CreateICMPv4TypeCode(8, 0),
			Id:       pid,
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		payload := []byte("hello world")
		err = gopacket.SerializeLayers(buf, opts, icpm,
			gopacket.Payload(payload))

		printError(err)

		conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstaddr})
		// fmt.Printf("向%s发送第%v个ICMP packet\n",dstip,i)
	}

	defer conn.Close()

	// fmt.Println(hex.Dump(buf.Bytes()))
	err = conn.SetDeadline(time.Now().Add(4 * time.Second))
	printError(err)

	cnt := 0

	for {

		recbuf := make([]byte, 4096)
		n, addr, err := conn.ReadFrom(recbuf)
		//printError(err)
		if err != nil {
			// fmt.Println("read error")
			return false
		} else if addr.String() == dstip {
			packet := gopacket.NewPacket(recbuf[:n], layers.LayerTypeICMPv4, gopacket.Default)
			if icmplayer := packet.Layer(layers.LayerTypeICMPv4); icmplayer != nil {
				icmp, _ := icmplayer.(*layers.ICMPv4)
				if icmp.Id == pid {
					cnt++
					// log.Printf("收到%s发回的第%v个ICMP包",dstip,cnt)
				}
				if cnt > 0 {
					log.Printf("%s is online", dstip)
					return true
				}
			}
		}
	}

}

func IsRoot() bool {
	return os.Geteuid() == 0
}

func CheckRoot() {
	if !IsRoot() {
		fmt.Println("must run with root")
		os.Exit(0)
	}
}

func main() {

	CheckRoot()
	var (
		startport int
		endport   int
		err       error
		finscan   bool = false
	)

	// m := make(map[int]bool)

	if len(os.Args) == 4 {
		scan_type := os.Args[1]
		ip := os.Args[2]
		ports := os.Args[3]

		if strings.Contains(ports, "-") {
			sli := strings.Split(ports, "-")
			startport, _ = strconv.Atoi(sli[0])
			endport, _ = strconv.Atoi(sli[1])
		} else {
			if startport, err = strconv.Atoi(ports); err == nil {
				endport = startport
			} else {
				log.Println(err)
				return
			}
		}

		cnt := 0
		if strings.Compare(scan_type, "-syn") == 0 {
			for port := startport; port <= endport; port++ {
				wg.Add(1)
				go SynScan(ip, port)
				cnt = (cnt + 1) % 10
				if cnt == 0 {
					time.Sleep(time.Millisecond * 50)
				}
			}
		} else if strings.Compare(scan_type, "-full") == 0 {
			for port := startport; port <= endport; port++ {
				wg.Add(1)
				go FullScan(ip, port)
				cnt = (cnt + 1) % 10
				if cnt == 0 {
					time.Sleep(time.Millisecond * 10)
				}
			}
		} else if strings.Compare(scan_type, "-fin") == 0 {
			finscan = true
			wg.Add(1)

			go Listen()

			time.Sleep(1 * time.Second)
			// fmt.Println(startport, endport)

			for port := startport; port <= endport; port++ {
				wg.Add(1)
				//go FinScan(ip, port, m)
				// fmt.Println(port, "go")
				go FinScan(ip, port)
				cnt = (cnt + 1) % 10
				if cnt == 0 {
					time.Sleep(time.Millisecond * 10)
				}
			}

			go func() {
				select {
				case <-time.After(5 * time.Second):
					handle.Close()
				}
			}()
		}
	} else if len(os.Args) == 3 {
		scan_type := os.Args[1]
		ips := os.Args[2]

		if scan_type == "-icmp" {

			if !strings.Contains(ips, "-") {
				ip := ips
				wg.Add(1)
				go IcmpScan(ip, 3)
			} else {
				l := strings.Split(ips, "-")
				addr1 := strings.Split(l[0], ".")
				addr2 := strings.Split(l[1], ".")
				addr_start := make([]int, 0)
				addr_end := make([]int, 0)
				for _, i := range addr1 {
					j, _ := strconv.Atoi(i)
					addr_start = append(addr_start, j)
				}
				for _, i := range addr2 {
					j, _ := strconv.Atoi(i)
					addr_end = append(addr_end, j)
				}

				fmt.Println(addr_start, addr_end)

				for a := addr_start[0]; a <= addr_end[0]; a++ {
					for b := addr_start[1]; b <= addr_end[1]; b++ {
						for c := addr_start[2]; c <= addr_end[2]; c++ {
							for d := addr_start[3]; d <= addr_end[3]; d++ {
								ip := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
								wg.Add(1)
								go IcmpScan(ip, 3)
								// fmt.Println(ip)
							}
						}
					}
				}

			}
			time.Sleep(1 * time.Second)
		}
	}

	wg.Wait()


	if finscan {
		for port := startport; port <= endport; port++ {
			if !ps[port] {
				log.Printf("%v : %v 打开了\n", os.Args[2], port)
			}
		}
		// fmt.Println(m)
	}
}

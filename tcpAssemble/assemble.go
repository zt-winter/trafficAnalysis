package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)
var iface = flag.String("i", "wlan0", "Interface to get packets from")
var fname = flag.String("r", "/home/zt/tls.pcapng", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")
var allowmissinginit = flag.Bool("allowmissinginit", true, "Support streams without SYN/SYN+ACK/ACK sequence")
var port = flag.Int("p", 80, "Interface to read packets from")


/*
 * HTTP part
 */

type httpGroup struct {
    req          *http.Request
    reqFirstLine string
    reqTimeStamp int64
    reqFlag      int //0=new,1=found,2=finish

    resp          *http.Response
    respFirstLine string
    respTimeStamp int64
    respFlag      int //0=new,1=found,2=finish
}


type httpReader struct {
	ident     string
	isClient  bool
	bytes     chan []byte
    timeStamp chan int64
	data      []byte
	hexdump   bool
	parent    *tcpStream
	logbuf    string
	srcip     string
	dstip     string
	srcport   string
	dstport   string
    httpstart int // 0 = new,1=find, 2 = old and find new
}


/*
 * TCP stream
 */

/* It's a connection (bidirectional) */
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	isHTTP         bool
	reversed       bool
	client         httpReader
	server         httpReader
	urls           []string
	ident          string
    all            []httpGroup
    hg             sync.Mutex
	sync.Mutex
}

type tcpStreamFactory struct{
	wg sync.WaitGroup
	doHTTP bool
}

func (h *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	sip, dip := net.Endpoints()
	srcip := fmt.Sprintf("%s", sip)
	dstip := fmt.Sprintf("%s", dip)

	fmsOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}
	stream := &tcpStream{
		net: net,
		transport: transport,
		isHTTP: (tcp.SrcPort == layers.TCPPort(*port) || tcp.DstPort == layers.TCPPort(*port)) && factory.doHTTP,

	}
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

func main() {
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Printf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Printf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()


	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <- packets:
			if packet == nil {
				fmt.Println((*streamPool))
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

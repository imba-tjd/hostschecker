package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	DefaultPathWin   = "C:/Windows/System32/drivers/etc/hosts"
	DefaultPathLinux = "/etc/hosts"
	ChannelCap       = 3
)

var (
	Timeout          = 5
	DialThreadsLimit = 2
)

type Pair struct {
	IP       string
	Hostname string
}

func main() {
	file := parseCmd()

	err := CheckHosts(file)
	if err != nil {
		panic(err)
	}
}

func parseCmd() string {
	var default_path string
	if runtime.GOOS == "windows" {
		default_path = DefaultPathWin
	} else {
		default_path = DefaultPathLinux
	}

	file := flag.String("path", default_path, "Hosts file to check")
	debug := flag.Bool("debug", false, "Enable verbose logging")
	flag.IntVar(&Timeout, "timeout", Timeout, "Timeout for connection")
	flag.IntVar(&DialThreadsLimit, "threads", DialThreadsLimit, "Max threads number for connection")

	flag.Parse()

	if !*debug {
		log.SetOutput(io.Discard)
	}
	return *file
}

// CheckHosts 读取指定的文件，输出处理结果，返回未知错误
func CheckHosts(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := TrimU8Bom(f); err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	ch, done := GenPairs(scanner)
	result := ConsumePairs(ch)

	var err2 error
	go func() {
		<-done
		if err := scanner.Err(); err != nil {
			err2 = err
		}
		close(ch)
	}()

	var count int
	for s := range result {
		count++
		fmt.Println(s)
	}

	if err2 != nil {
		return err2
	} else {
		fmt.Println("total mismatch:", count)
		return nil
	}
}

// GenPairs 按行读文件，用ParseLine处理，判断IP是否合法，返回 IP-域名 一对一的Pair的生成器
func GenPairs(scanner *bufio.Scanner) (chan Pair, <-chan struct{}) {
	ch := make(chan Pair, ChannelCap)
	done := make(chan struct{})

	go func() {
		for scanner.Scan() {
			ip, hostnames := ParseLine(scanner.Text())
			if ip == "" {
				continue
			}

			if _, err := netip.ParseAddr(ip); err != nil {
				log.Println("Invalid ip", ip) // TODO: 感觉上应该把消息传出去，但是没地方传
				continue
			} else {
				log.Println("Scanned", ip, hostnames)
			}

			for _, hostname := range hostnames {
				ch <- Pair{ip, hostname}
			}
		}
		done <- struct{}{}
	}()

	return ch, done
}

// ConsumePairs 多线程检查Channel中的Pair，返回不正确的结果。如果IP已经超时则跳过
func ConsumePairs(ch <-chan Pair) <-chan string {
	result := make(chan string, ChannelCap)

	go func() {
		th_lim := make(chan struct{}, DialThreadsLimit)
		var wg sync.WaitGroup

		for p := range ch {
			th_lim <- struct{}{}
			wg.Add(1)

			go func(p Pair) {
				defer func() {
					<-th_lim
					wg.Done()
				}()

				if _, ok := timedoutIP[p.IP]; ok {
					return
				}

				if ok, err := Hello(p); !ok {
					if os.IsTimeout(err) {
						result <- fmt.Sprint(p, " i/o timeout")
					} else {
						result <- fmt.Sprint(p, err)
					}
				}

			}(p)
		}

		wg.Wait()
		close(result)
	}()

	return result
}

// ParseLine 处理一行，去掉注释，按空白字符分割，第一个作为IP
// 注意返回的ip可以无效，hostnames可以为空
func ParseLine(line string) (ip string, hostnames []string) {
	line_trimmed := strings.TrimSpace(line)
	if len(line_trimmed) == 0 || line_trimmed[0] == '#' {
		return
	}
	hash_ndx := strings.IndexRune(line_trimmed, '#')
	if hash_ndx != -1 {
		line_trimmed = line_trimmed[:hash_ndx]
	}
	data := strings.Fields(line_trimmed)
	return data[0], data[1:]
}

var timedoutIP = map[string]struct{}{}

// Hello 与指定目标进行TCP连接和TLS握手
// 可能的情况：超时（包括封IP和不支持HTTPS）、SNI不匹配、SNI RST（）、成功
func Hello(p Pair) (bool, error) {
	conf := &tls.Config{
		ServerName: p.Hostname,
	}
	timeout := time.Duration(Timeout) * time.Second

	log.Println("Dialing", p)
	conn, err := net.DialTimeout("tcp", p.IP+":443", timeout)
	if err != nil {
		if os.IsTimeout(err) {
			timedoutIP[p.IP] = struct{}{}
		}
		return false, err
	}
	conn.(*net.TCPConn).SetLinger(0)
	defer conn.Close()

	tls_conn := tls.Client(conn, conf)
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	err = tls_conn.HandshakeContext(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
}

func TrimU8Bom(f *os.File) error {
	b := make([]byte, 3)
	n, err := f.Read(b)
	if err != nil {
		return err
	}

	if !(n == 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) {
		f.Seek(0, io.SeekStart)
	}
	return nil
}

package sipparser

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const (
	SIP_MSG_BUF_SEPERATOR = "========"
)

type SipMsgBuf struct {
	Name string
	Buf  []byte
}

func NewSipMsgBuf() *SipMsgBuf {
	return &SipMsgBuf{}
}

func (this *SipMsgBuf) Read(src []byte, pos int) (newPos int, ret int) {
	len1 := len(src)
	newPos = pos
	p1 := bytes.Index(src[newPos:], []byte(SIP_MSG_BUF_SEPERATOR))
	if p1 == -1 {
		return newPos, -1
	}
	newPos += p1

	p1 = bytes.IndexByte(src[newPos:], '\n')
	if p1 == -1 {
		return newPos, -1
	}
	newPos += p1 + 1

	for ; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		return newPos, -1
	}

	if !bytes.Equal(src[newPos:newPos+4], []byte("name")) {
		fmt.Printf("ERROR: not name after seperator at %d\n", newPos)
		return newPos, 1
	}

	newPos += 4

	for ; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		fmt.Printf("ERROR: reach end after name at %d\n", newPos)
		return newPos, 2
	}

	if src[newPos] != '=' {
		fmt.Errorf("ERROR: not '=' after name at %d\n", newPos)
		return newPos, 3
	}
	newPos++

	for ; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		fmt.Printf("ERROR: reach end after '=' at %d\n", newPos)
		return newPos, 4
	}

	if src[newPos] != '"' {
		fmt.Printf("ERROR: not '\"' after '=' at %d\n", newPos)
		return newPos, 5
	}

	newPos++

	nameBegin := newPos

	p1 = bytes.IndexByte(src[newPos:], '"')
	if p1 == -1 {
		fmt.Printf("ERROR: not '\"' after name-value at %d\n", newPos)
		return newPos, 6
	}
	newPos += p1

	this.Name = string(src[nameBegin:newPos])

	newPos++

	for ; newPos < len1; newPos++ {
		if !IsLwsChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		fmt.Printf("ERROR: reach end after name-value at %d\n", newPos)
		return newPos, 7
	}

	bufBegin := newPos

	p1 = bytes.Index(src[newPos:], []byte(SIP_MSG_BUF_SEPERATOR))
	if p1 == -1 {
		fmt.Printf("ERROR: reach end after msg-value at %d\n", newPos)
		return newPos, 8
	}

	newPos += p1

	this.Buf = src[bufBegin : newPos-2]

	return newPos, 0
}

type SipMsgBufs struct {
	Size int
	Data map[string]*SipMsgBuf
}

func NewSipMsgBufs() *SipMsgBufs {
	return &SipMsgBufs{Data: make(map[string]*SipMsgBuf)}
}

func (this *SipMsgBufs) ReadFromFile(filename string) bool {
	if this.Size > 0 {
		return true
	}

	src, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Errorf("ERROR: read file %s failed, err =\n", filename, err.Error())
		return false
	}

	pos := 0
	len1 := len(src)

	var ret int

	for {
		buf := NewSipMsgBuf()
		pos, ret = buf.Read(src, pos)
		if ret == -1 {
			return true
		} else if ret != 0 {
			fmt.Println("ERROR: ret =", ret)
			return false
		}

		this.Data[buf.Name] = buf
		this.Size++

		if pos >= len1 {
			break
		}
	}

	return true
}

var g_sip_msgs *SipMsgBufs = NewSipMsgBufs()

func ReadSipMsgBufs() *SipMsgBufs {
	filename := filepath.FromSlash(os.Args[len(os.Args)-1] + "/src/testdata/sip_msg.txt")
	g_sip_msgs.ReadFromFile(filename)
	//fmt.Println("g_sip_msgs.Size", g_sip_msgs.Size)
	return g_sip_msgs
}

/*func TestSipMsgBufsReadFromFile(t *testing.T) {
	bufs := ReadSipMsgBufs()
	p := bufs.Data["sip_flow_reg_message_200"]

	fmt.Printf("bufs[\"sip_flow_reg_message_200\"] = \n%s", string(p.Buf))
}*/

var msg string = "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
	"Content-Length: 226\r\n" +
	"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
	"From: \"User ID\" <sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
	"To: <sip:6135000@24.15.255.4>\r\n" +
	"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
	"CSeq: 101 INVITE\r\n" +
	//"Expires: 180\r\n" +
	//"User-Agent: Cisco-SIP-IP-Phone/2\r\n" +
	//"Accept: application/sdp\r\n" +
	"Contact: sip:6140000@24.15.255.101:5060\r\n" +
	"Content-Type: application/sdp\r\n" +
	"\r\n"

func BenchmarkSipMsgRawScan(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		ok := SipMsgRawScan(context)
		if !ok {
			fmt.Println("SipMsgRawScan3 failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Println("newPos =", context.parsePos)
}

func BenchmarkSipMsgRawScan_1(b *testing.B) {
	b.StopTimer()
	bufs := ReadSipMsgBufs()
	msg1 := bufs.Data["sip_flow_reg_register"].Buf
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		ok := SipMsgRawScan(context)
		if !ok {
			fmt.Println("SipMsgRawScan3 failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Println("newPos =", context.parsePos)
}

func BenchmarkSipMsgRawScan_2(b *testing.B) {
	b.StopTimer()
	bufs := ReadSipMsgBufs()
	msg1 := bufs.Data["sip_flow_reg_register_100"].Buf
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		ok := SipMsgRawScan(context)
		if !ok {
			fmt.Println("SipMsgRawScan3 failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Println("newPos =", context.parsePos)
}

func BenchmarkSipMsgsRawScan(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := []*SipMsgBuf{
		bufs.Data["sip_flow_reg_register"],
		bufs.Data["sip_flow_reg_register_100"],
	}

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				context.parsePos = 0
				ok := SipMsgRawScan(context)
				if !ok {
					fmt.Println("%s parse failed, err =", v.Name, context.Errors.String())
					fmt.Println("msg = \n", string(msg))
					return
				}
			}
		})
	}
}

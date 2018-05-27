package sipparser

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/lioneagle/goutil/src/test"
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
	Size  int
	Data  map[string]*SipMsgBuf
	Names []string
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
		this.Names = append(this.Names, buf.Name)
		this.Size++

		if pos >= len1 {
			break
		}
	}

	return true
}

func (this *SipMsgBufs) GetFilteredData(filter string) (ret []*SipMsgBuf) {
	if len(filter) == 0 {
		filter = "."
	}

	if filter != "." {
		for _, v := range this.Names {
			_, ok := ByteSliceIndexNoCase([]byte(v), 0, []byte(filter))
			if ok {
				ret = append(ret, this.Data[v])
			}
		}
	} else {
		for _, v := range this.Names {
			ret = append(ret, this.Data[v])
		}
	}

	return ret
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

func TestPrintSipMsgsParseMemUsed(t *testing.T) {

	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.ParseSipHeaderAsRaw = false

	type memUsed struct {
		name    string
		srcLen  int
		memUsed int
	}

	var memUsedList []*memUsed

	bufs := ReadSipMsgBufs()

	//testdata := bufs.GetFilteredData("flow_reg")
	testdata := bufs.GetFilteredData(".")

	maxNameLen := 0

	for _, v := range testdata {
		msg := v.Buf
		context.allocator.FreeAll()
		addr := NewSipMsg(context)
		sipmsg := addr.GetSipMsg(context)
		context.SetParseSrc(msg)
		context.SetParsePos(0)
		ok := sipmsg.Parse(context)
		if !ok {
			fmt.Println("parse sip msg failed, err =", context.Errors.String())
			fmt.Println("msg = ", string(msg))
			return
		}

		mem := &memUsed{}
		mem.name = v.Name
		mem.srcLen = len(v.Buf)
		mem.memUsed = int(context.allocator.Used())

		if len(mem.name) > maxNameLen {
			maxNameLen = len(mem.name)
		}

		memUsedList = append(memUsedList, mem)
	}

	//sort.Slice(memUsedList,func(i,j int){ return memUsedList[i].name < memUsedList[j].name})

	fmt.Printf("name")
	PrintIndent(os.Stdout, maxNameLen+4+len("MemUsed/"))
	fmt.Printf("%-5s  %-5s  %-5s  %-5s", "src,", "mem,", "delta,", "percent\n")

	totalSrcLen := 0
	totalMemUsed := 0
	for _, v := range memUsedList {
		totalSrcLen += v.srcLen
		totalMemUsed += v.memUsed
		fmt.Printf("MemUsed/%s", v.name)
		PrintIndent(os.Stdout, maxNameLen+4-len(v.name))
		delta := v.memUsed - v.srcLen
		fmt.Printf(":  %5d, %5d,  %5d,  %.2f%%\n", v.srcLen, v.memUsed, delta, 100*float64(delta)/float64(v.srcLen))
	}
	totalDelta := totalMemUsed - totalSrcLen
	fmt.Printf("MemUsed/total")
	PrintIndent(os.Stdout, maxNameLen+4-len("total"))
	fmt.Printf(":  %5d, %5d,  %5d,  %.2f%%\n", totalSrcLen, totalMemUsed, totalDelta, 100*float64(totalDelta)/float64(totalSrcLen))

}

func PrintIndent(w io.Writer, indent int) {
	fmt.Fprintf(w, fmt.Sprintf("%%%ds", indent), "")
}

func TestSipMsgParseWithoutBody(t *testing.T) {

	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"INVITE sip:123@a.com SIP/2.0\r\nFrom: sip:abc@a.com;tag=1\r\nAllow: a, b\r\nContent-Length: 123\r\n\r\n", true, len("INVITE sip:123@a.com SIP/2.0\r\nFrom: sip:abc@a.com;tag=1\r\nAllow: a, b\r\nContent-Length: 123\r\n\r\n"), "INVITE sip:123@a.com SIP/2.0\r\nFrom: <sip:abc@a.com>;tag=1\r\nContent-Length:        123\r\nAllow: a, b\r\n\r\n"},
		{"INVITE sip:123@a.com SIP/2.0\r\nFrom: sip:abc@a.com;tag=1\r\nAllow: a, b\r\n\r\n", true, len("INVITE sip:123@a.com SIP/2.0\r\nFrom: sip:abc@a.com;tag=1\r\nAllow: a, b\r\n\r\n"), "INVITE sip:123@a.com SIP/2.0\r\nFrom: <sip:abc@a.com>;tag=1\r\nContent-Length:          0\r\nAllow: a, b\r\n\r\n"},
		{"INVITE sip:123@a.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.189.156.16:5061;branch=z9hG4bK123, SIP/2.0/UDP 10.189.156.16:5062;branch=z9hG4bK124\r\n , SIP/2.0/UDP 10.189.156.16:5064;branch=z9hG4bK126\r\nAllow: a, b\r\nVia: SIP/2.0/UDP 10.189.156.16:5063;branch=z9hG4bK125\r\nFrom: sip:abc@a.com;tag=1\r\n\r\n", true, len("INVITE sip:123@a.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.189.156.16:5061;branch=z9hG4bK123, SIP/2.0/UDP 10.189.156.16:5062;branch=z9hG4bK124\r\n , SIP/2.0/UDP 10.189.156.16:5064;branch=z9hG4bK126\r\nAllow: a, b\r\nVia: SIP/2.0/UDP 10.189.156.16:5063;branch=z9hG4bK125\r\nFrom: sip:abc@a.com;tag=1\r\n\r\n"), "INVITE sip:123@a.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.189.156.16:5061;branch=z9hG4bK123, SIP/2.0/UDP 10.189.156.16:5062;branch=z9hG4bK124, SIP/2.0/UDP 10.189.156.16:5064;branch=z9hG4bK126, SIP/2.0/UDP 10.189.156.16:5063;branch=z9hG4bK125\r\nFrom: <sip:abc@a.com>;tag=1\r\nContent-Length:          0\r\nAllow: a, b\r\n\r\n"},

		{" INVITE sip:123@a.com SIP/2.0\r\n", false, 0, ""},
		{"INVITE sip:123@a.com SIP/2.0\r\n", false, len("INVITE sip:123@a.com SIP/2.0\r\n"), ""},
		{"INVITE sip:123@a.com SIP/2.0\r\nVia:", false, len("INVITE sip:123@a.com SIP/2.0\r\nVia:"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			ok := sipmsg.Parse(context)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, sipmsg.String(context), v.encode, "")
		})
	}
}

func TestSipMsg1RawParseAndEncode(t *testing.T) {
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	context.ParseSipHeaderAsRaw = true

	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)

	ok := sipmsg.Parse(context)
	test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

	buf := NewAbnfByteBuffer(nil)
	sipmsg.Encode(context, buf)

	//fmt.Println("msg =", buf.String())
}

func TestSipMsgParseWithOneBody(t *testing.T) {
	src := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Content-Length: 10\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"From: \"User ID\" <sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Disposition: render\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"Content-XYZ: 123\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"Contact: sip:6140000@24.15.255.101:5060\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		"1234567890"

	dst := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"Contact: <sip:6140000@24.15.255.101:5060>\r\n" +
		"From: \"User ID\"<sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"Content-Length:         10\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Disposition: render\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"Content-XYZ: 123\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"\r\n" +
		"1234567890"

	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.SetParseSrc([]byte(src))
	context.SetParsePos(0)

	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)

	ok := sipmsg.Parse(context)
	test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

	encoded := sipmsg.String(context)
	test.EXPECT_EQ(t, encoded, dst, "")
}

func TestSipMsgParseWithMultiBody(t *testing.T) {
	boundary := "simple-boundary"
	src := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Content-Length: 10\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"From: \"User ID\" <sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Contact: sip:6140000@24.15.255.101:5060\r\n" +
		"Content-Type: multipart/mixed;boundary=" + boundary + "\r\n" +
		"\r\n" +
		"--" + boundary + "padding\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"\r\n" +
		"1234567890" +
		"\r\n" +
		"--" + boundary + "padding\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"\r\n" +
		"abcsdfsdfsf" +
		"\r\n" +
		"--" + boundary + "--"

	dst := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"Contact: <sip:6140000@24.15.255.101:5060>\r\n" +
		"From: \"User ID\"<sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"Content-Length:        138\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Type: multipart/mixed;boundary=" + boundary + "\r\n" +
		"MIME-Version: 1.0\r\n" +

		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"\r\n" +
		"1234567890" +
		"\r\n" +
		"--" + boundary + "\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"\r\n" +
		"abcsdfsdfsf" +
		"\r\n" +
		"--" + boundary + "--"

	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.SetParseSrc([]byte(src))
	context.SetParsePos(0)

	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)

	ok := sipmsg.Parse(context)
	test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

	encoded := sipmsg.String(context)
	test.EXPECT_EQ(t, encoded, dst, "")
}

func TestSipMsgParseWithMultiBodyRemoveContentType(t *testing.T) {
	boundary := "simple-boundary"
	src := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Content-Length: 10\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"From: \"User ID\" <sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Contact: sip:6140000@24.15.255.101:5060\r\n" +
		"Content-Type: multipart/mixed;boundary=" + boundary + "\r\n" +
		"\r\n" +
		"--" + boundary + "padding\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"\r\n" +
		"1234567890" +
		"\r\n" +
		"--" + boundary + "padding\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"\r\n" +
		"abcsdfsdfsf" +
		"\r\n" +
		"--" + boundary + "--"

	dst := "INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 24.15.255.101:5060\r\n" +
		"Contact: <sip:6140000@24.15.255.101:5060>\r\n" +
		"From: \"User ID\"<sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe\r\n" +
		"To: <sip:6135000@24.15.255.4>\r\n" +
		"Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101\r\n" +
		"Content-Length:        186\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Type: multipart/mixed;boundary=\"" + ABNF_SIP_DEFAULT_BOUNDARY + "\"\r\n" +
		"MIME-Version: 1.0\r\n" +

		"\r\n" +
		"--" + ABNF_SIP_DEFAULT_BOUNDARY + "\r\n" +
		"Content-Encoding: gzip, tar\r\n" +
		"\r\n" +
		"1234567890" +
		"\r\n" +
		"--" + ABNF_SIP_DEFAULT_BOUNDARY + "\r\n" +
		"Content-XYZ: abc, def\r\n" +
		"\r\n" +
		"abcsdfsdfsf" +
		"\r\n" +
		"--" + ABNF_SIP_DEFAULT_BOUNDARY + "--"

	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.SetParseSrc([]byte(src))
	context.SetParsePos(0)

	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)

	ok := sipmsg.Parse(context)
	test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

	sipmsg.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE] = ABNF_PTR_NIL

	encoded := sipmsg.String(context)
	test.EXPECT_EQ(t, encoded, dst, "")
}

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

func BenchmarkSipMsg1Parse(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.SetParseSrc(msg1)
	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		ok := sipmsg.Parse(context)
		if !ok {
			fmt.Println("SipMsgRawScan3 failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Printf("msg = %s\n", sipmsg.String(context))
	//fmt.Printf("allocator.AllocNum = %d\n", context.allocator.AllocNum())
	//fmt.Println("context.allocator.Used() =", context.allocator.Used()-remain)
	//fmt.Println("remain =", remain)
}

func BenchmarkSipMsg1RawParse(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 10)
	context.SetParseSrc(msg1)
	context.ParseSipHeaderAsRaw = true
	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		ok := sipmsg.Parse(context)
		if !ok {
			fmt.Println("SipMsgRawScan3 failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Printf("msg = %s\n", sipmsg.String(context))
	//fmt.Printf("allocator.AllocNum = %d\n", context.allocator.AllocNum())
	//fmt.Println("context.allocator.Used() =", context.allocator.Used()-remain)
	//fmt.Println("remain =", remain)
}

func BenchmarkSipMsg1Encode(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)
	sipmsg.Parse(context)
	remain := context.allocator.Used()
	buf := NewAbnfByteBuffer(nil)

	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		sipmsg.Encode(context, buf)
	}
	//fmt.Println("msg =", buf.String())
}

func BenchmarkSipMsg1RawEncode(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	context.ParseSipHeaderAsRaw = true
	addr := NewSipMsg(context)
	sipmsg := addr.GetSipMsg(context)
	sipmsg.Parse(context)
	remain := context.allocator.Used()
	buf := NewAbnfByteBuffer(nil)

	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		sipmsg.Encode(context, buf)
	}
	//fmt.Println("msg =", buf.String())
}

func BenchmarkSipMsgRawScan(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
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
	context := NewContext()
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
	context := NewContext()
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

//var sip_msgs_filter = "flow_reg"
var sip_msgs_filter = "."
var encodeSipUriNoEscape = true

func BenchmarkSipMsgsRawScan(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

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

func BenchmarkSipMsgsParse(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			remain := context.allocator.Used()

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				context.parsePos = 0
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				ok := sipmsg.Parse(context)
				if !ok {
					fmt.Println("%s parse failed, err =", v.Name, context.Errors.String())
					fmt.Println("msg = \n", string(msg))
					return
				}
			}
		})
	}
}

func BenchmarkSipMsgsEncode(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			sipmsg.Parse(context)
			remain := context.allocator.Used()
			buf := NewAbnfByteBuffer(nil)

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				buf.Reset()
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				sipmsg.Encode(context, buf)
			}
		})
	}
}

func BenchmarkSipMsgsForKeyHeadersParse(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	infos := g_SipHeaderInfos.Clone()
	for _, v := range infos {
		if v != nil {
			v.NeedParse = false
		}
	}
	infos[SIP_HDR_FROM].NeedParse = true
	infos[SIP_HDR_TO].NeedParse = true
	infos[SIP_HDR_CSEQ].NeedParse = true
	infos[SIP_HDR_CALL_ID].NeedParse = true
	//infos[SIP_HDR_VIA].NeedParse = true
	infos[SIP_HDR_RECORD_ROUTE].NeedParse = true
	infos[SIP_HDR_CONTENT_TYPE].NeedParse = true
	infos[SIP_HDR_CONTENT_LENGTH].NeedParse = true

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.SipHeaders = infos
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			remain := context.allocator.Used()

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				context.parsePos = 0
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				ok := sipmsg.Parse(context)
				if !ok {
					fmt.Println("%s parse failed, err =", v.Name, context.Errors.String())
					fmt.Println("msg = \n", string(msg))
					return
				}
			}
		})
	}
}

func BenchmarkSipMsgsForKeyHeadersEncode(b *testing.B) {
	bufs := ReadSipMsgBufs()

	infos := g_SipHeaderInfos.Clone()
	for _, v := range infos {
		if v != nil {
			v.NeedParse = false
		}
	}
	infos[SIP_HDR_FROM].NeedParse = true
	infos[SIP_HDR_TO].NeedParse = true
	infos[SIP_HDR_CSEQ].NeedParse = true
	infos[SIP_HDR_CALL_ID].NeedParse = true
	//infos[SIP_HDR_VIA].NeedParse = true
	infos[SIP_HDR_RECORD_ROUTE].NeedParse = true
	infos[SIP_HDR_CONTENT_TYPE].NeedParse = true
	infos[SIP_HDR_CONTENT_LENGTH].NeedParse = true

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.SipHeaders = infos
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			sipmsg.Parse(context)
			remain := context.allocator.Used()
			buf := NewAbnfByteBuffer(nil)

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				buf.Reset()
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				sipmsg.Encode(context, buf)
			}
		})
	}
}

func BenchmarkSipMsgsRawParse(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.ParseSipHeaderAsRaw = true
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			remain := context.allocator.Used()

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				context.parsePos = 0
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				ok := sipmsg.Parse(context)
				if !ok {
					fmt.Println("%s parse failed, err =", v.Name, context.Errors.String())
					fmt.Println("msg = \n", string(msg))
					return
				}
			}
		})
	}
}

func BenchmarkSipMsgsRawEncode(b *testing.B) {
	bufs := ReadSipMsgBufs()

	testdata := bufs.GetFilteredData(sip_msgs_filter)

	for _, v := range testdata {
		v := v

		b.Run(v.Name, func(b *testing.B) {
			//b.Parallel()

			b.StopTimer()

			msg := v.Buf
			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(msg))
			context.SetParsePos(0)
			context.ParseSipHeaderAsRaw = true
			context.EncodeUriNoEscape = encodeSipUriNoEscape

			addr := NewSipMsg(context)
			sipmsg := addr.GetSipMsg(context)
			sipmsg.Parse(context)
			remain := context.allocator.Used()
			buf := NewAbnfByteBuffer(nil)

			b.SetBytes(2)
			b.ReportAllocs()
			b.StartTimer()

			b.StartTimer()

			for i := 0; i < b.N; i++ {
				buf.Reset()
				context.allocator.ClearAllocNum()
				context.allocator.FreePart(remain)
				sipmsg.Encode(context, buf)
			}
		})
	}
}

func BenchmarkFindSipHeader1(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	name := []byte("Content-Type:")
	buf := NewAbnfByteBuffer(nil)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.parsePos = 0
		ok := FindSipHeader1(context, name, buf)
		if !ok {
			fmt.Println("BenchmarkFindSipHeader failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}
}

func BenchmarkFindSipHeader2(b *testing.B) {
	b.StopTimer()
	msg1 := []byte(msg)
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(msg1)
	name := []byte("Content-Type")
	shortname := []byte("c")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	//newPos := AbnfPos(0)
	ok := false
	for i := 0; i < b.N; i++ {
		context.parsePos = 0
		//newPos, ok = FindSipHeader2(context, name, shortname)
		_, ok = FindSipHeader2(context, name, shortname)
		if !ok {
			fmt.Println("BenchmarkFindSipHeader failed, err =", context.Errors.String())
			fmt.Println("msg1 = ", string(msg1))
			break
		} //*/
	}

	//fmt.Println("ok =", ok)
	//fmt.Println("newPos =", newPos)
	//fmt.Println("msg1[newPos:] =", string(msg1[newPos:]))
}

package sipparser

import (
	//"bytes"
	"fmt"
	"testing"
)

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

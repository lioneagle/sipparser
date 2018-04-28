package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipMethodParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		method byte
		encode string
	}{
		{"INVITE: sip:abc@a.com", true, len("INVITE"), ABNF_SIP_METHOD_INVITE, "INVITE"},
		/*{"PRACK: sip:abc@a.com", true, len("PRACK"), ABNF_SIP_METHOD_PRACK, "PRACK"},
		{"UPDATE: sip:abc@a.com", true, len("UPDATE"), ABNF_SIP_METHOD_UPDATE, "UPDATE"},
		{"INFO: sip:abc@a.com", true, len("INFO"), ABNF_SIP_METHOD_INFO, "INFO"},
		{"ACK: sip:abc@a.com", true, len("ACK"), ABNF_SIP_METHOD_ACK, "ACK"},
		{"BYE: sip:abc@a.com", true, len("BYE"), ABNF_SIP_METHOD_BYE, "BYE"},
		{"REGISTER: sip:abc@a.com", true, len("REGISTER"), ABNF_SIP_METHOD_REGISTER, "REGISTER"},
		{"SUBSCRIBE: sip:abc@a.com", true, len("SUBSCRIBE"), ABNF_SIP_METHOD_SUBSCRIBE, "SUBSCRIBE"},
		{"NOTIFY: sip:abc@a.com", true, len("NOTIFY"), ABNF_SIP_METHOD_NOTIFY, "NOTIFY"},
		{"REFER: sip:abc@a.com", true, len("REFER"), ABNF_SIP_METHOD_REFER, "REFER"},
		{"OPTIONS: sip:abc@a.com", true, len("OPTIONS"), ABNF_SIP_METHOD_OPTIONS, "OPTIONS"},
		{"MESSAGE: sip:abc@a.com", true, len("MESSAGE"), ABNF_SIP_METHOD_MESSAGE, "MESSAGE"},
		{"PUBLISH: sip:abc@a.com", true, len("PUBLISH"), ABNF_SIP_METHOD_PUBLISH, "PUBLISH"},
		{"INVITE1: sip:abc@a.com", true, len("INVITE1"), ABNF_SIP_METHOD_UNKNOWN, "INVITE1"},
		{"iNVITE: sip:abc@a.com", true, len("iNVITE"), ABNF_SIP_METHOD_UNKNOWN, "iNVITE"},*/
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipMethod(context)
			method := addr.GetSipMethod(context)

			ok := method.Parse(context)
			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, method.String(context), v.encode, "")
		})
	}
}

func BenchmarkSipMethodParse1(b *testing.B) {
	b.StopTimer()
	v := []byte("INVITE: sip:abc@a.com")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipMethod(context)
	method := addr.GetSipMethod(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		method.Parse(context)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipMethodParse2(b *testing.B) {
	b.StopTimer()
	v := []byte("INVITExxxxxx: sip:abc@a.com")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipMethod(context)
	method := addr.GetSipMethod(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		method.Parse(context)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipMethodEncode1(b *testing.B) {
	b.StopTimer()
	v := []byte("INVITE: sip:abc@a.com")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipMethod(context)
	method := addr.GetSipMethod(context)
	method.Parse(context)
	remain := context.allocator.Used()
	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		method.Encode(context, buf)
	}

	//fmt.Println("header =", buf.String())
}

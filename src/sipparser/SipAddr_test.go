package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipAddrParseScheme(t *testing.T) {
	testdata := []struct {
		src      string
		ok       bool
		newPos   int
		scheme   string
		addrType byte
	}{
		{"sip:123", true, len("sip:"), "sip", ABNF_URI_SIP},
		{"sIP:123", true, len("sip:"), "sip", ABNF_URI_SIP},
		{"sips:abc", true, len("sips:"), "sips", ABNF_URI_SIPS},
		{"SipS:abc", true, len("sips:"), "sips", ABNF_URI_SIPS},
		{"tel:456", true, len("tel:"), "tel", ABNF_URI_TEL},
		{"tEl:456", true, len("tel:"), "tel", ABNF_URI_TEL},
		{"urn:sos", true, len("urn:"), "urn", ABNF_URI_URN},
		{"http://sos", true, len("http:"), "http", ABNF_URI_ABSOLUTE},
		{"sipst://sos", true, len("sipst:"), "sipst", ABNF_URI_ABSOLUTE},
		{"sipx://sos", true, len("sipx:"), "sipx", ABNF_URI_ABSOLUTE},

		{"", false, 0, "", ABNF_URI_UNKNOWN},
		{":", false, 0, "", ABNF_URI_UNKNOWN},
		{"1sip:", false, 0, "", ABNF_URI_UNKNOWN},
		{"sip=:", false, 3, "", ABNF_URI_UNKNOWN},
		{"sips", false, 4, "", ABNF_URI_UNKNOWN},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			ptr := NewSipAddr(context)
			addr := ptr.GetSipAddr(context)

			ok := addr.ParseScheme(context)
			if v.ok {
				test.EXPECT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.EXPECT_FALSE(t, ok, "")
			}
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, addr.addrType, v.addrType, "")

			if v.addrType == ABNF_URI_ABSOLUTE {
				test.EXPECT_NE(t, addr.scheme, ABNF_PTR_NIL, "")
				test.EXPECT_EQ(t, addr.scheme.CString(context), v.scheme, "")
			}
		})
	}
}

func BenchmarkSipAddrParseScheme(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	remain := context.allocator.Used()
	context.SetParseSrc(v)
	context.SetParsePos(0)
	ptr := NewSipAddr(context)
	addr := ptr.GetSipAddr(context)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		//context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		addr.ParseScheme(context)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

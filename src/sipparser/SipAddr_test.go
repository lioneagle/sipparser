package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipAddrParseScheme(t *testing.T) {
	testdata := []struct {
		src     string
		ok      bool
		newPos  int
		scheme  string
		uriType byte
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
				test.EXPECT_EQ(t, addr.addrType, ABNF_SIP_ADDR_SPEC, "")

			} else {
				test.EXPECT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, addr.uriType, v.uriType, "")

			if v.uriType == ABNF_URI_ABSOLUTE {
				test.EXPECT_NE(t, addr.scheme, ABNF_PTR_NIL, "")
				test.EXPECT_EQ(t, addr.scheme.CString(context), v.scheme, "")
			}
		})
	}
}

func TestSipAddrParseAddrSpec(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", true, len("sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"), "sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"},
		{"sips:123:tsdd@[1080::8:800:200c:417a]:5061", true, len("sips:123:tsdd@[1080::8:800:200c:417a]:5061"), "sips:123:tsdd@[1080::8:800:200c:417a]:5061"},
		//{"tel:861234;phone-context=+123", true, len("tel:861234;phone-context=+123"), "tel:861234;phone-context=+123"},

		//{"httpx://861234/phone-context=+123", false, len("httpx:"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			ptr := NewSipAddr(context)
			addr := ptr.GetSipAddr(context)

			ok := addr.Parse(context, true)
			if v.ok {
				test.EXPECT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.EXPECT_FALSE(t, ok, "")
			}
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, addr.String(context), v.encode, "")
		})
	}
}

func TestSipAddrParseNameAddr(t *testing.T) {

	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"<sip:abc@a.com>", true, len("<sip:abc@a.com>"), "<sip:abc@a.com>"},
		{"<sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa>", true, len("<sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa>"), "<sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa>"},
		{"\"abc\"<sips:123:tsdd@[1080::8:800:200c:417a]:5061>", true, len("\"abc\"<sips:123:tsdd@[1080::8:800:200c:417a]:5061>"), "\"abc\"<sips:123:tsdd@[1080::8:800:200c:417a]:5061>"},
		{"abc def ee<sip:861234;phone-context=+123>", true, len("abc def ee<sip:861234;phone-context=+123>"), "abc def ee<sip:861234;phone-context=+123>"},
		//{"abc def ee<tel:861234;phone-context=+123>", true, len("abc def ee<tel:861234;phone-context=+123>"), "abc def ee<tel:861234;phone-context=+123>"},

		{"\"", false, len("\""), ""},
		//{"\r\n<tel:123>", false, len(""), ""},
		//{"a b@ c<tel:123>", false, len("a b"), ""},
		//{"<tel:", false, len("<tel:"), ""},
		//{"<tel:123", false, len("<tel:123"), ""},
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

			ok := addr.Parse(context, true)
			if v.ok {
				test.EXPECT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.EXPECT_FALSE(t, ok, "")
			}
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, addr.String(context), v.encode, "")
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

func BenchmarkSipAddrParseAddrSpec(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	remain := context.allocator.Used()
	context.SetParseSrc(v)
	context.SetParsePos(0)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		ptr := NewSipAddr(context)
		addr := ptr.GetSipAddr(context)
		addr.ParseWithoutInit(context, true)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipAddrParseNameAddr(b *testing.B) {
	b.StopTimer()
	v := []byte("\"string\" <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	remain := context.allocator.Used()
	context.SetParseSrc(v)
	context.SetParsePos(0)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		ptr := NewSipAddr(context)
		addr := ptr.GetSipAddr(context)
		addr.ParseWithoutInit(context, true)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

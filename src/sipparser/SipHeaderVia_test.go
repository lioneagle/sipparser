package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderViaParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123", true, len("Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123"), "Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123"},
		{"Via: SIP/2/UDP 10.4.1.1:5070;branch=123", true, len("Via: SIP/2/UDP 10.4.1.1:5070;branch=123"), "Via: SIP/2/UDP 10.4.1.1:5070;branch=123"},
		{"Via: SIP \r\n\t/\r\n 2.0\t/ UDP \r\n\t10.4.1.1:5070;branch=123", true, len("Via: SIP \r\n\t/\r\n 2.0\t/ UDP \r\n\t10.4.1.1:5070;branch=123"), "Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123"},

		{" Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123", false, 0, ""},
		{"Via2: SIP/2.0/UDP 10.4.1.1:5070;branch=123", false, 0, ""},
		{"Via: SIP/2.0UDP 10.4.1.1:5070;branch=123", false, len("Via: SIP/2.0"), ""},
		{"Via: SIP/2.0/@ 10.4.1.1:5070;branch=123", false, len("Via: SIP/2.0/"), ""},
		{"Via: SIP/2.0/UDP\r\n10.4.1.1:5070;branch=123", false, len("Via: SIP/2.0/UDP\r\n"), ""},
		{"Via:", false, len("Via:"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderVia(context)
			header := addr.GetSipHeaderVia(context)

			ok := header.Parse(context)
			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, header.String(context), v.encode, "")
		})
	}
}

func TestSipHeaderViaParse2(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Via: SIP/2.0/UDP 10.4.1.1:5070;xxx;ttl=1;branch=123", true, len("Via: SIP/2.0/UDP 10.4.1.1:5070;xxx;ttl=1;branch=123"), "Via: SIP/2.0/UDP 10.4.1.1:5070;branch=123;ttl=1;xxx"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)
			context.ParseSetSipViaKnownParam = true

			addr := NewSipHeaderVia(context)
			header := addr.GetSipHeaderVia(context)

			ok := header.Parse(context)
			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, header.String(context), v.encode, "")
		})
	}
}

func BenchmarkSipHeaderViaParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Via: SIP/2.0/UDP 24.15.255.101:5060;branch=072c09e5.0")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderVia(context)
	header := addr.GetSipHeaderVia(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		header.Parse(context)
	}
	//fmt.Printf("header = %s\n", header.String())
	//fmt.Printf("allocator.AllocNum = %d, i= %d\n", context.allocator.AllocNum(), i)
	//fmt.Println("context.allocator.Used() =", context.allocator.Used()-remain)
	//fmt.Println("remain =", remain)
}

func BenchmarkSipHeaderViaEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Via: SIP/2.0/UDP 24.15.255.101:5060;branch=072c09e5.0")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderVia(context)
	header := addr.GetSipHeaderVia(context)
	header.Parse(context)
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
		header.Encode(context, buf)
	}

	//fmt.Println("header =", buf.String())
}

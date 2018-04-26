package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderRouteParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Route: <sip:abc@a.com>;tag=1", true, len("Route: <sip:abc@a.com>;tag=1"), "Route: <sip:abc@a.com>;tag=1"},
		{"routE: <sip:abc@a.com;user=ip>;tag=1", true, len("Route: <sip:abc@a.com;user=ip>;tag=1"), "Route: <sip:abc@a.com;user=ip>;tag=1"},
		{"Route: abc<sip:abc@a.com;user=ip>;tag=1", true, len("Route: abc<sip:abc@a.com;user=ip>;tag=1"), "Route: abc<sip:abc@a.com;user=ip>;tag=1"},
		//{"Route: <tel:+12358;tag=123>", true, len("Route: <tel:+12358;tag=123>"), "Route: <tel:+12358;tag=123>"},

		{" Route: <sip:abc@a.com>;tag=1", false, 0, "0"},
		{"Route: sip:abc@a.com;tag=1", false, len("Route: sip"), "0"},
		{"Route1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Route: ", false, len("Route: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderRoute(context)
			header := addr.GetSipHeaderRoute(context)

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

func BenchmarkSipHeaderRouteParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Route: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRoute(context)
	header := addr.GetSipHeaderRoute(context)
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

func BenchmarkSipHeaderRouteEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Route: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRoute(context)
	header := addr.GetSipHeaderRoute(context)
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

package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderRecordRouteParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Record-Route: <sip:abc@a.com>;tag=1", true, len("Record-Route: <sip:abc@a.com>;tag=1"), "Record-Route: <sip:abc@a.com>;tag=1"},
		{"REcord-roUte: <sip:abc@a.com;user=ip>;tag=1", true, len("Record-Route: <sip:abc@a.com;user=ip>;tag=1"), "Record-Route: <sip:abc@a.com;user=ip>;tag=1"},
		{"Record-Route: abc<sip:abc@a.com;user=ip>;tag=1", true, len("Record-Route: abc<sip:abc@a.com;user=ip>;tag=1"), "Record-Route: abc<sip:abc@a.com;user=ip>;tag=1"},
		{"Record-Route: <tel:+12358;tag=123>", true, len("Record-Route: <tel:+12358;tag=123>"), "Record-Route: <tel:+12358;tag=123>"},

		{" Record-Route: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Record-Route: sip:abc@a.com;tag=1", false, len("Record-Route: sip"), ""},
		{"Record-Route1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Record-Route: ", false, len("Record-Route: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderRecordRoute(context)
			header := addr.GetSipHeaderRecordRoute(context)

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

func BenchmarkSipHeaderRecordRouteParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Record-Route: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRecordRoute(context)
	header := addr.GetSipHeaderRecordRoute(context)
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

func BenchmarkSipHeaderRecordRouteEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Record-Route: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRecordRoute(context)
	header := addr.GetSipHeaderRecordRoute(context)
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

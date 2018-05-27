package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderPathParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Path: <sip:abc@a.com>;tag=1", true, len("Path: <sip:abc@a.com>;tag=1"), "Path: <sip:abc@a.com>;tag=1"},
		{"pAtH: <sip:abc@a.com;user=ip>;tag=1", true, len("pAtH: <sip:abc@a.com;user=ip>;tag=1"), "Path: <sip:abc@a.com;user=ip>;tag=1"},
		{"Path: abc<sip:abc@a.com;user=ip>;tag=1", true, len("Path: abc<sip:abc@a.com;user=ip>;tag=1"), "Path: abc<sip:abc@a.com;user=ip>;tag=1"},
		{"Path: <tel:+12358;tag=123>", true, len("Path: <tel:+12358;tag=123>"), "Path: <tel:+12358;tag=123>"},

		{" Path: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Path: sip:abc@a.com;tag=1", false, len("Path: sip"), ""},
		{"Path1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Path: ", false, len("Path: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderPath(context)
			header := addr.GetSipHeaderPath(context)

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

func BenchmarkSipHeaderPathParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Path: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderPath(context)
	header := addr.GetSipHeaderPath(context)
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

func BenchmarkSipHeaderPathEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Path: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderPath(context)
	header := addr.GetSipHeaderPath(context)
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

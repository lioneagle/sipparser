package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderToParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"To: sip:abc@a.com;tag=1", true, len("To: sip:abc@a.com;tag=1"), "To: sip:abc@a.com;tag=1"},
		{"t: <sip:abc@a.com;user=ip>;tag=1", true, len("t: <sip:abc@a.com;user=ip>;tag=1"), "To: <sip:abc@a.com;user=ip>;tag=1"},
		{"tO: abc<sip:abc@a.com;user=ip>;tag=1", true, len("tO: abc<sip:abc@a.com;user=ip>;tag=1"), "To: abc<sip:abc@a.com;user=ip>;tag=1"},
		//{"To: tel:+12358;tag=123", true, len("To: tel:+12358;tag=123"), "To: <tel:+12358>;tag=123"},

		{" To: <sip:abc@a.com>;tag=1", false, 0, "0"},
		{"To1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"To: ", false, len("To: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderTo(context)
			header := addr.GetSipHeaderTo(context)

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

func BenchmarkSipHeaderToParse(b *testing.B) {
	b.StopTimer()
	v := []byte("To: <sip:6135000@24.15.255.4>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderTo(context)
	header := addr.GetSipHeaderTo(context)
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
	//fmt.Printf("header = %s\n", header.String(context))
	//fmt.Printf("allocator.AllocNum = %d, i= %d\n", context.allocator.AllocNum(), i)
	//fmt.Println("context.allocator.Used() =", context.allocator.Used()-remain)
	//fmt.Println("remain =", remain)
}

func BenchmarkSipHeaderToEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("To: <sip:6135000@24.15.255.4>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderTo(context)
	header := addr.GetSipHeaderTo(context)
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

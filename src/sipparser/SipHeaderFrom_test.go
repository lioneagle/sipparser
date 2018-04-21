package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderFromParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"From: sip:abc@a.com;tag=1", true, len("From: sip:abc@a.com;tag=1"), "From: sip:abc@a.com;tag=1"},
		{"f: <sip:abc@a.com;user=ip>;tag=1", true, len("f: <sip:abc@a.com;user=ip>;tag=1"), "From: <sip:abc@a.com;user=ip>;tag=1"},
		{"frOm: abc<sip:abc@a.com;user=ip>;tag=1", true, len("frOm: abc<sip:abc@a.com;user=ip>;tag=1"), "From: abc<sip:abc@a.com;user=ip>;tag=1"},
		//{"From: tel:+12358;tag=123", true, len("From: tel:+12358;tag=123"), "From: <tel:+12358>;tag=123"},

		{" From: <sip:abc@a.com>;tag=1", false, 0, "0"},
		{"From1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"From: ", false, len("From: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderFrom(context)
			header := addr.GetSipHeaderFrom(context)

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

func BenchmarkSipHeaderFromParse(b *testing.B) {
	b.StopTimer()
	//v := []byte("From: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	//v := []byte("From: \"User ID\" <sip:6140000@24.15.255.4>;tag=dab70900252036d7134be-4ec05abe")
	v := []byte("From: \"User ID\" <sip:abc@biloxi.com;transport=tcp;method=REGISTER>;tag=dab70900252036d7134be-4ec05abe")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderFrom(context)
	header := addr.GetSipHeaderFrom(context)
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
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipHeaderFromEncode(b *testing.B) {
	b.StopTimer()
	//v := []byte("From: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	v := []byte("From: \"User ID\" <sip:abc@biloxi.com;transport=tcp;method=REGISTER>;tag=dab70900252036d7134be-4ec05abe")
	//v := []byte("From:<sip:abc@biloxi.com>;tag=dab70900252036d7134be-4ec05abe")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderFrom(context)
	header := addr.GetSipHeaderFrom(context)
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

//*
func BenchmarkSipHeaderFromString(b *testing.B) {
	b.StopTimer()
	v := []byte("From: \"User ID\" <sip:abc@biloxi.com;transport=tcp;method=REGISTER>;tag=dab70900252036d7134be-4ec05abe")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderFrom(context)
	header := addr.GetSipHeaderFrom(context)
	header.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		header.String(context)
	}
} //*/

package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderCallIdParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Call-ID: abc123@a.com", true, len("Call-ID: abc123@a.com"), "Call-ID: abc123@a.com"},
		{"i: abc123", true, len("i: abc123"), "Call-ID: abc123"},
		{"caLL-iD: abc123\r\n", true, len("Call-ID: abc123"), "Call-ID: abc123"},

		{" Call-ID: abc123@", false, 0, ""},
		{"Call-ID1: abc123@", false, 0, ""},
		{"Call-ID: abc123@", false, len("Call-ID: abc123@"), ""},
		{"Call-ID: @abc", false, len("Call-ID: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderCallId(context)
			header := addr.GetSipHeaderCallId(context)

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

func BenchmarkSipHeaderCallIdParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderCallId(context)
	header := addr.GetSipHeaderCallId(context)
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

func BenchmarkSipHeaderCallIdEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Call-ID: 0009b7da-0352000f-30a69b83-0e7b53d6@24.15.255.101")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderCallId(context)
	header := addr.GetSipHeaderCallId(context)
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

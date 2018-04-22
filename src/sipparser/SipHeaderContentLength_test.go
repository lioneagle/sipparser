package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderContentLengthParse(t *testing.T) {
	testdata := []struct {
		src       string
		ok        bool
		newPos    int
		encode    string
		encodeEnd int
	}{
		{"Content-Length: 1234", true, len("Content-Length: 1234"), "Content-Length:       1234", len("Content-Length:       1234")},
		{"contenT-LengtH: 1234", true, len("Content-Length: 1234"), "Content-Length:       1234", len("Content-Length:       1234")},
		{"l: 1234", true, len("l: 1234"), "Content-Length:       1234", len("Content-Length:       1234")},

		{" Content-Lengt: 1234", false, 0, "", 0},
		{"Content-Lengt: 1234", false, 0, "", 0},
		{"Content-Length: ", false, len("Content-Length: "), "", 0},
		{"Content-Length: a123", false, len("Content-Length: "), "", 0},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderContentLength(context)
			header := addr.GetSipHeaderContentLength(context)

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
			test.EXPECT_EQ(t, header.encodeEnd, uint32(v.encodeEnd), "")
		})
	}
}

func BenchmarkSipHeaderContentLengthParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Length: 2226")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentLength(context)
	header := addr.GetSipHeaderContentLength(context)
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
	//fmt.Printf("allocator.Used = %d, i= %d\n", context.allocator.Used(), i)
}

func BenchmarkSipHeaderContentLengthEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Length: 2226")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentLength(context)
	header := addr.GetSipHeaderContentLength(context)
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

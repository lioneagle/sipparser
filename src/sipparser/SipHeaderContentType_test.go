package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderContentTypeParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Content-Type: application/sdp", true, len("Content-Type: application/sdp"), "Content-Type: application/sdp"},
		{"conteNt-TypE: application/sdp", true, len("Content-Type: application/sdp"), "Content-Type: application/sdp"},
		{"c: message/sip", true, len("c: message/sip"), "Content-Type: message/sip"},

		{" Content-Type: abc", false, 0, ""},
		{"Content-Type2: abc", false, 0, ""},
		{"Content-Type: ", false, len("Content-Type: "), ""},
		{"Content-Type: abc", false, len("Content-Type: abc"), ""},
		{"Content-Type: abc/", false, len("Content-Type: abc/"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderContentType(context)
			header := addr.GetSipHeaderContentType(context)

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

func TestSipHeaderContentTypeParse2(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Content-Type: application/sdp;abc;boundary=123", true, len("Content-Type: application/sdp;abc;boundary=123"), "Content-Type: application/sdp;boundary=123;abc"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderContentType(context)
			header := addr.GetSipHeaderContentType(context)

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

func BenchmarkSipHeaderContentTypeParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Type: application/sdp")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentType(context)
	header := addr.GetSipHeaderContentType(context)
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

func BenchmarkSipHeaderContentTypeEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Type: application/sdp")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentType(context)
	header := addr.GetSipHeaderContentType(context)
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

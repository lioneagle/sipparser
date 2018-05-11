package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderContentDispositionParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Content-Disposition: session", true, len("Content-Disposition: session"), "Content-Disposition: session"},
		{"contenT-dispOsitioN: early-session", true, len("Content-Disposition: early-session"), "Content-Disposition: early-session"},

		{" Content-Disposition: abc", false, 0, ""},
		{"Content-Disposition2: abc", false, 0, ""},
		{"Content-Disposition: ", false, len("Content-Disposition: "), ""},
		{"Content-Disposition: @", false, len("Content-Disposition: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderContentDisposition(context)
			header := addr.GetSipHeaderContentDisposition(context)

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

func TestSipHeaderContentDispositionParse2(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Content-Disposition: session;abc;handling=optional", true, len("Content-Disposition: session;abc;handling=optional"), "Content-Disposition: session;handling=optional;abc"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)
			context.ParseSetSipContentDispositionKnownParam = true

			addr := NewSipHeaderContentDisposition(context)
			header := addr.GetSipHeaderContentDisposition(context)

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

func BenchmarkSipHeaderContentDispositionParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Disposition: early-session;handling=optional")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentDisposition(context)
	header := addr.GetSipHeaderContentDisposition(context)
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

func BenchmarkSipHeaderContentDispositionEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Content-Disposition: early-session;handling=optional")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContentDisposition(context)
	header := addr.GetSipHeaderContentDisposition(context)
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

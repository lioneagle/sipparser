package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderCseqParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"CSeq: 1234 INVITE", true, len("CSeq: 1234 INVITE"), "CSeq: 1234 INVITE"},

		{" CSeq: ", false, 0, ""},
		{"CSeq2: ", false, 0, ""},
		{"CSeq: ", false, len("CSeq: "), ""},
		{"CSeq: 1234", false, len("CSeq: 1234"), ""},
		{"CSeq: 1234 \r\nINVITE", false, len("CSeq: 1234 \r\n"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderCseq(context)
			header := addr.GetSipHeaderCseq(context)

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

func BenchmarkSipHeaderCseqParse(b *testing.B) {
	b.StopTimer()
	v := []byte("CSeq: 101 INVITE")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderCseq(context)
	header := addr.GetSipHeaderCseq(context)
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

func BenchmarkSipHeaderCseqEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("CSeq: 101 INVITE")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderCseq(context)
	header := addr.GetSipHeaderCseq(context)
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

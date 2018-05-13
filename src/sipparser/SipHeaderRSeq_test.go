package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderRSeqParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"RSeq: 1234", true, len("RSeq: 1234"), "RSeq: 1234"},
		{"rSeQ: 1234", true, len("rSeQ: 1234"), "RSeq: 1234"},

		{" RSeq: 1234", false, 0, ""},
		{"RSe: 1234", false, 0, ""},
		{"RSeq: ", false, len("RSeq: "), ""},
		{"RSeq: a123", false, len("RSeq: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderRSeq(context)
			header := addr.GetSipHeaderRSeq(context)

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

func BenchmarkSipHeaderRSeqParse(b *testing.B) {
	b.StopTimer()
	v := []byte("RSeq: 2226")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRSeq(context)
	header := addr.GetSipHeaderRSeq(context)
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

func BenchmarkSipHeaderRSeqEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("RSeq: 2226")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderRSeq(context)
	header := addr.GetSipHeaderRSeq(context)
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

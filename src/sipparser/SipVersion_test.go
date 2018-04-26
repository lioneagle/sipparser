package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipVersionParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Sip/2.0", true, len("Sip/2.0"), "SIP/2.0"},
		{"Sip/22.10", true, len("Sip/22.10"), "SIP/22.10"},

		{"Si", false, 0, ""},
		{"Sip", false, 0, ""},
		{"abc/2.0", false, 0, ""},
		{"Sip/a.b", false, len("Sip/"), ""},
		{"Sip/20^b", false, len("Sip/20"), ""},
		{"Sip/20.b", false, len("Sip/20."), ""},
		{"Sip/.b0", false, len("Sip/"), ""},
		{"sip\t/.b", false, 0, ""},
		{"sip \t/.b", false, 0, ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipVersion(context)
			version := addr.GetSipVersion(context)

			ok := version.Parse(context)
			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, version.String(context), v.encode, "")
		})
	}
}

func BenchmarkSipVersionParse(b *testing.B) {
	b.StopTimer()
	v := []byte("SIP/2.0")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipVersion(context)
	version := addr.GetSipVersion(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		version.Parse(context)
	}
	//fmt.Printf("version = %s\n", version.String())
	//fmt.Printf("")
}

func BenchmarkSipVersionEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("SIP/2.0")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipVersion(context)
	version := addr.GetSipVersion(context)
	version.Parse(context)
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
		version.Encode(context, buf)
	}

	//fmt.Println("version =", buf.String())
}

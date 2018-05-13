package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderPAssertedIdentityParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"P-Asserted-Identity: sip:abc@a.com", true, len("P-Asserted-Identity: sip:abc@a.com"), "P-Asserted-Identity: <sip:abc@a.com>"},
		{"p-AssErted-IdeNtity: <sip:abc@a.com;user=ip>", true, len("p-AssErted-IdeNtity: <sip:abc@a.com;user=ip>"), "P-Asserted-Identity: <sip:abc@a.com;user=ip>"},
		{"P-Asserted-Identity: abc<sip:abc@a.com;user=ip>", true, len("P-Asserted-Identity: abc<sip:abc@a.com;user=ip>"), "P-Asserted-Identity: abc<sip:abc@a.com;user=ip>"},
		{"P-Asserted-Identity: <tel:+12358;tag=123>", true, len("P-Asserted-Identity: <tel:+12358;tag=123>"), "P-Asserted-Identity: <tel:+12358;tag=123>"},

		{" P-Asserted-Identity: <sip:abc@a.com>", false, 0, ""},
		{"P-Asserted-Identity1: sip:abc@a.com", false, 0, ""},
		{"P-Asserted-Identity: ", false, len("P-Asserted-Identity: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHeaderPAssertedIdentity(context)
			header := addr.GetSipHeaderPAssertedIdentity(context)

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

func BenchmarkSipHeaderPAssertedIdentityParse(b *testing.B) {
	b.StopTimer()
	v := []byte("P-Asserted-Identity: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderPAssertedIdentity(context)
	header := addr.GetSipHeaderPAssertedIdentity(context)
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

func BenchmarkSipHeaderPAssertedIdentityEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("P-Asserted-Identity: <sip:abc@biloxi.com;transport=tcp;method=REGISTER>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderPAssertedIdentity(context)
	header := addr.GetSipHeaderPAssertedIdentity(context)
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

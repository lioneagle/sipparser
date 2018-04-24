package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestAbnfPtrCStringEqualNoCase(t *testing.T) {
	testdata := []struct {
		src string
	}{
		{"user"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			//addr := AllocCString(context, []byte(v.src))
			addr, ok := context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_PNAME, ABNF_CHARSET_MASK_SIP_PNAME)
			test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
			test.ASSERT_TRUE(t, ok, "")
			test.EXPECT_TRUE(t, addr.CStringEqualNoCase(context, []byte(v.src)), "")
		})
	}
}

func BenchmarkAbnfPtrStrlen(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	data := []byte("01234567890123456789")
	addr := AllocCString(context, data)
	//len1 := 0
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		//len1 = addr.Strlen(context)
		addr.Strlen(context)
	}

	//fmt.Println("len =", len1)
}

func BenchmarkAbnfPtrStrlen2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	data := []byte("01234567890123456789")
	addr := AllocCString(context, data)
	//len1 := 0
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		//len1 = addr.Strlen2(context)
		addr.Strlen2(context)
	}

	//fmt.Println("len2 =", len1)
}

package sipparser

import (
	//"fmt"
	"testing"

	//"github.com/lioneagle/goutil/src/test"
)

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

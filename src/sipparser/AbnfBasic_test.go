package sipparser

import (
	"bytes"
	"fmt"
	"testing"
	"unsafe"

	"github.com/lioneagle/goutil/src/buffer"
	"github.com/lioneagle/goutil/src/chars"
	"github.com/lioneagle/goutil/src/test"
)

func TestParseUIntOK(t *testing.T) {
	testdata := []struct {
		src    string
		digit  uint
		num    uint32
		newPos AbnfPos
	}{
		{"1234567890.abc", 1234567890, 10, 10},
		{"10.40.1.1", 10, 2, 2},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			digit, num, newPos, ok := ParseUInt([]byte(v.src), 0)

			test.ASSERT_TRUE(t, ok, "")
			test.EXPECT_EQ(t, digit, v.digit, "")
			test.EXPECT_EQ(t, num, v.num, "")
			test.EXPECT_EQ(t, newPos, v.newPos, "")
		})
	}
}

func TestEncodeUIntWithWidth(t *testing.T) {
	buf := buffer.NewByteBuffer(nil)
	EncodeUIntWithWidth(buf, 123, 10)
	test.EXPECT_EQ(t, buf.String(), "       123", "")
}

func TestAllocCString(t *testing.T) {
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%39")

	addr := AllocCString(context, src)

	test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
	test.EXPECT_EQ(t, addr.CString(context), string(src), "")
}

func TestAllocCStringWithUnescape(t *testing.T) {
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%39")

	addr := AllocCStringWithUnescapeNum(context, src, 3)

	test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
	test.EXPECT_EQ(t, addr.CString(context), "0123456789", "")
}

func TestParseLWS2(t *testing.T) {
	testdata := []struct {
		src    string
		newPos AbnfPos
		ok     bool
	}{
		{"", 0, true},
		{"  \t", 3, true},
		{"\r\n \t", 4, true},
		{"\r\n\t ", 4, true},
		{"\t  \r\n\t ", 7, true},
		{"     \t\t\t\t\t\r\n    ", 16, true},
		{"     \t\t\t\t\t\r\n    xy", 16, true},

		{"\t  \r\n", 5, false},
		{"\t  \r\nab", 5, false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			newPos, ok := ParseLWS_2([]byte(v.src), 0)

			test.EXPECT_EQ(t, ok, v.ok, "")
			test.EXPECT_EQ(t, newPos, v.newPos, "")
		})
	}
}

func TestParseLWS1(t *testing.T) {
	testdata := []struct {
		src    string
		newPos AbnfPos
		ok     bool
	}{
		{"", 0, true},
		{"  \t", 3, true},
		{"\r\n \t", 4, true},
		{"\r\n\t ", 4, true},
		{"\t  \r\n\t ", 7, true},
		{"     \t\t\t\t\t\r\n    ", 16, true},
		{"     \t\t\t\t\t\r\n    xy", 16, true},

		{"\t  \r\n", 5, false},
		{"\t  \r\nab", 5, false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024)
			context.SetParseSrc([]byte(v.src))

			ok := ParseLWS(context)

			test.EXPECT_EQ(t, ok, v.ok, "")
			test.EXPECT_EQ(t, context.parsePos, v.newPos, "")
		})
	}

}

func BenchmarkEqualNoCaseEqual1(b *testing.B) {
	b.StopTimer()
	var s1 = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var s2 = []byte("abcdefghijklmnopqrstuvwxyz")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		chars.EqualNoCase(s1, s2)
	}
}

func BenchmarkEqualNoCaseEqual2(b *testing.B) {
	b.StopTimer()
	s1 := []byte("abcdefghijklmnopqrstuvwxyz")
	s2 := []byte("abcdefghijklmnopqrstuvwxyz")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		chars.EqualNoCase(s1, s2)
	}
}

func BenchmarkEqualNoCaseEqual3(b *testing.B) {
	b.StopTimer()
	s1 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		chars.EqualNoCase(s1, s2)
	}
}

func BenchmarkBytesEqual(b *testing.B) {
	b.StopTimer()
	s1 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		bytes.Equal(s1, s2)
	}
}

func BytesEqual2(s1 []byte, s2 []byte) bool {
	len1 := len(s1)
	if len1 != len(s2) {
		return false
	}
	for i := 0; i < len1; i++ {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

func BytesEqual3(s1 []byte, s2 []byte) bool {
	len1 := len(s1)
	if len1 != len(s2) {
		return false
	}

	p1 := uintptr(unsafe.Pointer(&s1[0]))
	p2 := uintptr(unsafe.Pointer(&s2[0]))
	end := p1 + uintptr(len1)
	//end1 := p1 + uintptr((len1 % 0x7ffffffffffffff8))
	end1 := p1 + uintptr((len1>>3)<<3)
	//end1 := p1 + uintptr(len1/8)

	for p1 < end1 {
		if *((*int64)(unsafe.Pointer(p1))) != *((*int64)(unsafe.Pointer(p2))) {
			return false
		}
		p1 += 8
		p2 += 8
	}

	for p1 < end {
		if *((*byte)(unsafe.Pointer(p1))) != *((*byte)(unsafe.Pointer(p2))) {
			return false
		}
		p1++
		p2++
	}
	return true
}

func BenchmarkBytesEqual2(b *testing.B) {
	b.StopTimer()
	s1 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		BytesEqual2(s1, s2)
	}
}

func BenchmarkBytesEqual3(b *testing.B) {
	b.StopTimer()
	s1 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s2 := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		BytesEqual3(s1, s2)
	}
}

func BenchmarkParseUInt(b *testing.B) {
	b.StopTimer()

	src := []byte("12345")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ParseUInt(src, 0)
	}
}

func BenchmarkParseUInt_2(b *testing.B) {
	b.StopTimer()

	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("12345")
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.SetParsePos(0)
		ParseUInt_2(context)
	}
}

func BenchmarkParseUInt32(b *testing.B) {
	b.StopTimer()

	src := []byte("12345")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ParseUInt32(src, 0)
	}
}

func BenchmarkParseUInt16(b *testing.B) {
	b.StopTimer()

	src := []byte("12345")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ParseUInt16(src, 0)
	}
}

func BenchmarkParseUInt8(b *testing.B) {
	b.StopTimer()

	src := []byte("123")

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ParseUInt8(src, 0)
	}
}

func BenchmarkEncodeUInt(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUInt(buf, 1234567)
	}
}

func BenchmarkEncodeUInt32(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUInt32(buf, 1234567)
	}
}

func BenchmarkEncodeUInt2(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUInt2(buf, 1234567)
	}
}

func BenchmarkEncodeUInt3(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUInt(buf, 123)
	}

	//fmt.Printf("ret = +%s\n", buf.String())
}

func BenchmarkEncodeUIntWithWidth(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUIntWithWidth(buf, 123, 10)
	}
}

func BenchmarkEncodeUInt32WithWidth(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		EncodeUInt32WithWidth(buf, 123, 10)
	}

	//fmt.Printf("ret = +%s\n", buf.String())
}

func BenchmarkWriteDigitEscape(b *testing.B) {
	b.StopTimer()
	buf := buffer.NewByteBuffer(make([]byte, 1024*100))
	src := []byte("1234567abc")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteEscape(src, &g_charsets[ABNF_CHARSET_DIGIT], ABNF_CHARSET_MASK_DIGIT)
	}
}

func BenchmarkAllocCString(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%39")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCString(context, src)
	}
}

func BenchmarkAllocCString2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%39")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCString2(context, src)
	}
}

func BenchmarkAllocCStringWithUnescapeNum(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("01234560123456%37%38%39")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum(context, src, 3)
	}
}

func BenchmarkAllocCStringWithUnescapeNum2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%390123456")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum(context, src, 3)
	}
}

func BenchmarkAllocCStringWithUnescapeNum3(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("01234560123456137138139")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum(context, src, 0)
	}
}

func BenchmarkAllocCStringWithUnescapeNum_2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("01234560123456%37%38%39")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum2(context, src, 3)
	}
}

func BenchmarkAllocCStringWithUnescapeNum2_2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%390123456")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum2(context, src, 3)
	}
}

func BenchmarkAllocCStringWithUnescapeNum3_2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("01234560123456137138139")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescapeNum2(context, src, 0)
	}
}

func BenchmarkAllocCStringWithUnescape(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456%37%38%39")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescape(context, src)
	}
}

func BenchmarkAllocCStringWithUnescape2(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("%37%38%390123456")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescape(context, src)
	}
}

func BenchmarkAllocCStringWithUnescape3(b *testing.B) {
	b.StopTimer()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 10)
	src := []byte("0123456137138139")
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		AllocCStringWithUnescape(context, src)
	}

}

func BenchmarkZeroByteSlice(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	src := make([]byte, 30)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ZeroByteSlice(src)
	}
}

func BenchmarkZeroMem(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	src := make([]byte, 30)
	addr := uintptr(unsafe.Pointer(&src[0]))
	len1 := len(src)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ZeroMem(addr, len1)
	}
}

func BenchmarkMemcpy1(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	src := make([]byte, 128)
	dst := make([]byte, 128)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		copy(dst, src)
	}
}

func BenchmarkMemcpy2(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	src := make([]byte, 128)
	dst := make([]byte, 128)
	addr1 := uintptr(unsafe.Pointer(&src[0]))
	addr2 := uintptr(unsafe.Pointer(&dst[0]))
	len1 := len(src)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		Memcpy(addr2, addr1, len1)
	}
}

func BenchmarkMemcpy3(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 1024)
	len1 := 128
	src := context.allocator.Alloc(uint32(len1))
	dst := context.allocator.Alloc(uint32(len1))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		copy(dst.GetAsByteSlice(context, len1), src.GetAsByteSlice(context, len1))
	}
}

func BenchmarkMemcpy4(b *testing.B) {
	b.StopTimer()
	//src := []byte("012345678901234567890123456789")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 1024)
	len1 := 128
	src := context.allocator.Alloc(uint32(len1))
	dst := context.allocator.Alloc(uint32(len1))
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		dst.CopyFrom(context, src, len1)
	}
}

func BenchmarkParseEscapable1(b *testing.B) {
	b.StopTimer()
	src := []byte("+01234567890%230123456789")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseEscapable(context, src, 0, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkParseEscapable2(b *testing.B) {
	b.StopTimer()
	src := []byte("+01234567890%230123456789")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseEscapable2(context, src, 0, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkParseLWS1(b *testing.B) {
	b.StopTimer()
	src := []byte("     \t\t\t\t\t\r\n    ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLWS(context)
	}
}

func BenchmarkParseLWS2(b *testing.B) {
	b.StopTimer()
	src := []byte("     \t\t\t\t\t\r\n    ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLWS_2(src, 0)
	}
}

func BenchmarkParseSWS1(b *testing.B) {
	b.StopTimer()
	src := []byte("     \t\t\t\t\t\r\n    ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseSWS_2(context)
	}
}

func BenchmarkParseSWS1_2(b *testing.B) {
	b.StopTimer()
	src := []byte(" ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseSWS_2(context)
	}
}

func BenchmarkParseSWS2(b *testing.B) {
	b.StopTimer()
	src := []byte("     \t\t\t\t\t\r\n    ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseSWS(src, 0)
	}
}

func BenchmarkParseSWS2_2(b *testing.B) {
	b.StopTimer()
	src := []byte(" ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseSWS(src, 0)
	}
}

func BenchmarkParseLeftAngleQuote1_1(b *testing.B) {
	b.StopTimer()
	src := []byte(" <>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLeftAngleQuote(context)
	}
}

func BenchmarkParseLeftAngleQuote1_2(b *testing.B) {
	b.StopTimer()
	src := []byte("  \r\n\t <>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLeftAngleQuote(context)
	}
}

func BenchmarkParseLeftAngleQuote2_1(b *testing.B) {
	b.StopTimer()
	src := []byte(" <>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLeftAngleQuote2(context, src, 0)
	}
}

func BenchmarkParseLeftAngleQuote2_2(b *testing.B) {
	b.StopTimer()
	src := []byte("  \r\n\t <>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseLeftAngleQuote2(context, src, 0)
	}
}

func BenchmarkParseRightAngleQuote1_1(b *testing.B) {
	b.StopTimer()
	src := []byte("> ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseRightAngleQuote(context)
	}
}

func BenchmarkParseRightAngleQuote1_2(b *testing.B) {
	b.StopTimer()
	src := []byte(">  \r\n\t")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseRightAngleQuote(context)
	}
}

func BenchmarkParseRightAngleQuote2_1(b *testing.B) {
	b.StopTimer()
	src := []byte("> ")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseRightAngleQuote2(context, src, 0)
	}
}

func BenchmarkParseRightAngleQuote2_2(b *testing.B) {
	b.StopTimer()
	src := []byte(">  \r\n\t")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		ParseRightAngleQuote2(context, src, 0)
	}
}

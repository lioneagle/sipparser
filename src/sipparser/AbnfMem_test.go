package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

//*
func TestMemAllocatorAlloc(t *testing.T) {
	testdata := []struct {
		memSize   uint32
		allocSize uint32
		ok        bool
	}{
		{200, 1, true},
		{200, 199, true},

		{100, 0, false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			allocator := NewMemAllocator(v.memSize)

			test.ASSERT_NE(t, allocator, nil, "")
			test.ASSERT_EQ(t, allocator.Capacity(), v.memSize, "")

			addr := allocator.Alloc(v.allocSize)

			if v.ok {
				test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
			}

			if !v.ok {
				test.ASSERT_EQ(t, addr, ABNF_PTR_NIL, "")
			}
		})
	}
}

func TestMemAllocatorAllocEx(t *testing.T) {
	testdata := []struct {
		memSize      uint32
		allocSize    uint32
		memAllocSize uint32
		ok           bool
	}{
		{200, 1, ABNF_MEM_ALIGN, true},
		{200, ABNF_MEM_ALIGN + 1, 2 * ABNF_MEM_ALIGN, true},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			allocator := NewMemAllocator(v.memSize)

			test.ASSERT_NE(t, allocator, nil, "")
			test.ASSERT_EQ(t, allocator.Capacity(), v.memSize, "")

			addr, alloc := allocator.AllocEx(v.allocSize)

			if v.ok {
				test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
			}

			if !v.ok {
				test.ASSERT_EQ(t, addr, ABNF_PTR_NIL, "")
				return
			}

			test.EXPECT_EQ(t, alloc, v.memAllocSize, "")

		})
	}
}

func TestMemAllocatorUsed(t *testing.T) {
	testdata := []struct {
		allocSize uint32
		ok        bool
	}{
		{101, true},
		{203, true},
		//{-1, false},
		{0, false},
		{21, true},
		{1, true},
	}

	allocator := NewMemAllocator(1000)
	used := uint32(0)
	allocNum := uint32(0)
	allocNumOk := uint32(0)

	for i, v := range testdata {
		v := v
		allocNum++
		if v.ok {
			allocNumOk++
			used += v.allocSize
			used = RoundToAlign(used, ABNF_MEM_ALIGN)
		}

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			addr := allocator.Alloc(v.allocSize)

			if v.ok {
				test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
			}

			if !v.ok {
				test.ASSERT_EQ(t, addr, ABNF_PTR_NIL, "")
				return
			}

			test.EXPECT_EQ(t, allocator.Used(), used, "")
			test.EXPECT_EQ(t, allocator.AllocNum(), allocNum, "")
			test.EXPECT_EQ(t, allocator.AllocNumOk(), allocNumOk, "")
			test.EXPECT_EQ(t, allocator.FreeAllNum(), uint32(0), "")
			test.EXPECT_EQ(t, allocator.FreePartNum(), uint32(0), "")
		})
	}

	allocator.String(0, 128)
	allocator.String(-1, 128)
	allocator.String(10, 1)
	allocator.String(0, int(allocator.Capacity()+1))
	allocator.String(int(allocator.Capacity()+2), int(allocator.Capacity()+1))

	allocator.FreePart(100)
	test.EXPECT_EQ(t, allocator.Used(), uint32(100), "")

	allocator.FreePart(200)
	test.EXPECT_EQ(t, allocator.Used(), uint32(100), "")

	allocator.FreeAll()
	test.EXPECT_EQ(t, allocator.Used(), uint32(0), "")
}

func TestMemParseAndAllocCStringEscapable(t *testing.T) {

	testdata := []struct {
		name         string
		charsetIndex int
		mask         uint32
		src          string
		ok           bool
		begin        int32
		end          int32
		newPos       AbnfPos
		escapeNum    int
	}{
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "01234abc", true, 0, 5, 5, 0},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "56789=bc", true, 0, 5, 5, 0},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%301234abc", true, 0, 7, 7, 1},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%30%311234abc", true, 0, 10, 10, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%311234%30", true, 0, 10, 10, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%30%31123%3a", true, 0, 12, 12, 3},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "ad6789abc", false, 0, 0, 0, 0},

		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%3c%31123%", false, 0, 10, 9, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%30%31123%F", false, 0, 10, 9, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%3x%31123%F", false, 0, 0, 0, 2},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024)
			context.SetParseSrc([]byte(v.src))
			addr, ok := context.allocator.ParseAndAllocCStringEscapable(context, v.charsetIndex, v.mask)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "")
				test.ASSERT_NE(t, addr, ABNF_PTR_NIL, "")
			}

			if !v.ok {
				test.ASSERT_FALSE(t, ok, "")
				test.ASSERT_EQ(t, addr, ABNF_PTR_NIL, "")
			}

			test.ASSERT_EQ(t, context.parsePos, v.newPos, "")

			if !v.ok {
				return
			}
		})
	}
}

func TestMemParseAndAllocSipQuotedStringParseOK(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		wanted string
	}{
		{"\"\"", true, "\"\""},
		{"\"User ID\"", true, "\"User ID\""},
		{"\"abc\"", true, "\"abc\""},
		{"\"abc\\00\"", true, "\"abc\\00\""},
		{" \t\r\n \"abc\\00\\\"\"", true, "\"abc\\00\\\"\""},
		{" \t\r\n\t\"abc\\0b\"", true, "\"abc\\0b\""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr, ok := context.allocator.ParseAndAllocSipQuotedString(context)
			buf := NewAbnfByteBuffer(nil)
			EncodeSipQuotedString(context, buf, addr)

			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			test.EXPECT_EQ(t, buf.String(), v.wanted, "")
		})
	}
}

func TestMemParseAndAllocSipQuotedStringNOK(t *testing.T) {

	testdata := []struct {
		src    string
		newPos int
	}{
		{"abc\"", 0},
		{"\r\n\"abc\\00\"", 0},
		{"\r\n \"abc\\", len("\r\n\"abc\\")},
		{"\r\n \"abc\r\n\\", len("\r\n \"abc\r\n")},
		{"\r\n \"abc", len("\r\n \"abc")},
		{"\r\n \"abc€", len("\r\n \"abc") + 1},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr, ok := context.allocator.ParseAndAllocSipQuotedString(context)

			test.EXPECT_FALSE(t, ok, "")
			test.EXPECT_EQ(t, addr, ABNF_PTR_NIL, "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")
		})
	}
}

func BenchmarkMemAlloc(b *testing.B) {
	b.StopTimer()
	allocator := NewMemAllocator(1024 * 128)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		allocator.FreeAll()
		allocator.Alloc(1024)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	//fmt.Printf("")
}
func BenchmarkMemAllocEx(b *testing.B) {
	b.StopTimer()
	allocator := NewMemAllocator(1024 * 128)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		allocator.FreeAll()
		_, _ = allocator.AllocEx(1024)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	//fmt.Printf("")
}

func BenchmarkMemAllocWithClear(b *testing.B) {
	b.StopTimer()
	allocator := NewMemAllocator(1024 * 128)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		allocator.FreeAll()
		allocator.AllocWithClear(1024)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	//fmt.Printf("")
}

func BenchmarkParseAndAllocCStringEscapable1(b *testing.B) {
	b.StopTimer()
	src := []byte("+01234567890%230123456789")
	context := NewContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkParseAndAllocSipQuotedString(b *testing.B) {
	b.StopTimer()
	src := []byte("\"0123456789\"")
	context := NewContext()
	context.allocator = NewMemAllocator(1024)
	context.SetParseSrc(src)

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		context.allocator.ParseAndAllocSipQuotedString(context)
	}
}

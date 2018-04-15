package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestAbnfRefParse(t *testing.T) {
	testdata := []struct {
		name         string
		charsetIndex int
		mask         uint32
		src          string
		err          bool
		begin        int32
		end          int32
		newPos       AbnfPos
	}{

		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "01234abc", false, 0, 5, 5},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "56789=bc", false, 0, 5, 5},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "ad6789abc", true, 0, 0, 0},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			ref := AbnfRef{}
			newPos := ref.Parse([]byte(v.src), 0, v.charsetIndex, v.mask)

			test.ASSERT_EQ(t, ref.Begin, v.begin, "")
			test.ASSERT_EQ(t, ref.End, v.end, "")
			test.ASSERT_EQ(t, newPos, v.newPos, "")
		})
	}
}

func TestAbnfRefParseEscapable(t *testing.T) {

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
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "ad6789abc", true, 0, 0, 0, 0},

		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%3c%31123%", false, 0, 10, 9, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%30%31123%F", false, 0, 10, 9, 2},
		{"IsDigit", ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT, "%3x%31123%F", false, 0, 0, 0, 2},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			ref := AbnfRef{}
			escapeNum, newPos, ok := ref.ParseEscapable([]byte(v.src), 0, v.charsetIndex, v.mask)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "")
			}

			if !v.ok {
				test.ASSERT_FALSE(t, ok, "")

			}

			test.ASSERT_EQ(t, newPos, v.newPos, "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, ref.Begin, v.begin, "")
			test.EXPECT_EQ(t, ref.End, v.end, "")
			test.EXPECT_EQ(t, escapeNum, v.escapeNum, "")
		})
	}
}

func BenchmarkAbnfRefParseEscapableSipToken(b *testing.B) {
	b.StopTimer()
	data := []byte("+01234567890%230123456789")
	ref := &AbnfRef{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ref.Parse(data, 0, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	}
}

func BenchmarkAbnfRefParseEscapableSipUser1(b *testing.B) {
	b.StopTimer()
	data := []byte("+01234567890%230123456789")
	ref := &AbnfRef{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ref.ParseEscapable(data, 0, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkAbnfRefParseEscapableSipUser2(b *testing.B) {
	b.StopTimer()
	data := []byte("+01234567890%230123456789")
	ref := &AbnfRef{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ref.ParseEscapable2(data, 0, &g_charsets[ABNF_CHARSET_SIP_USER], ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkAbnfRefParseEscapableSipUser3(b *testing.B) {
	b.StopTimer()
	data := []byte("+01234567890%230123456789")
	ref := &AbnfRef{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ref.ParseEscapable3(data, 0, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
	}
}

func BenchmarkParseAndAllocSipToken1(b *testing.B) {
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
		ParseAndAllocSipToken(context, src, 0)
	}
}

func BenchmarkParseAndAllocSipToken2(b *testing.B) {
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
		ParseAndAllocSipToken2(context)
	}
}

package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestFindCrlfRFC3261(t *testing.T) {
	testdata := []struct {
		src   string
		ok    bool
		begin int
		end   int
	}{
		{"122334545\r\n", true, len("122334545"), len("122334545\r\n")},
		{"122334545\r\nadsad", true, len("122334545"), len("122334545\r\n")},
		{"122334545\n", true, len("122334545"), len("122334545\n")},
		{"122334545\nadsad", true, len("122334545"), len("122334545\n")},

		{"122334545", false, len("122334545"), len("122334545")},
		{"122334545\r", false, len("122334545\r"), len("122334545\r")},
		{"122334545\r\n ", false, len("122334545\r\n "), len("122334545\r\n ")},
		{"122334545\r\n\t", false, len("122334545\r\n\t"), len("122334545\r\n\t")},
		{"\r", false, 1, 1},
		{"\n", true, 0, 1},
		{"", false, 0, 0},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			begin, ok := FindCrlfByRFC3261(context)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, begin, AbnfPos(v.begin), "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.end), "")
		})
	}
}

func TestParseRawHeadersOk(t *testing.T) {
	testdata := []struct {
		src    string
		encode string
	}{
		{"From: test\r\nTo: test\r\nCall-ID: test\r\n", "From: test\r\nTo: test\r\nCall-ID: test\r\n"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			headers, ok := ParseRawHeaders(context)

			test.ASSERT_NE(t, headers, ABNF_PTR_NIL, "")
			test.ASSERT_TRUE(t, ok, "")

			buf := NewAbnfByteBuffer(nil)
			EncodeRawHeaders(context, headers, buf)

			test.EXPECT_EQ(t, buf.String(), v.encode, "")
		})
	}
}

func TestFindRawHeaders(t *testing.T) {
	testdata := []struct {
		src         string
		headerIndex SipHeaderIndexType
		ok          bool
	}{
		{"From: test\r\nTo: test\r\nCall-ID: test\r\n", SIP_HDR_CALL_ID, true},
		{"From: test\r\nTo: test\r\nCall-ID: test\r\n", SIP_HDR_CSEQ, false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			headers, ok := ParseRawHeaders(context)

			test.ASSERT_NE(t, headers, ABNF_PTR_NIL, "")
			test.ASSERT_TRUE(t, ok, "")

			_, ok = FindRawHeaderByIndex(context, headers, v.headerIndex)
			test.EXPECT_EQ(t, ok, v.ok, "")
		})
	}
}

func BenchmarkFindRawHeaderByIndex(b *testing.B) {
	b.StopTimer()
	v := []byte("From1: test\r\nFrom2: test\r\nFrom3: test\r\nFrom4: test\r\nFrom5: test\r\nFrom6: test\r\nTo: test\r\nCall-ID: test\r\n")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	headers, ok := ParseRawHeaders(context)
	if !ok {
		fmt.Println("parse raw header failed")
		return
	}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		FindRawHeaderByIndex(context, headers, SIP_HDR_CALL_ID)
	}
}

func BenchmarkParseHeaderNameAndGetSipHeaderIndex(b *testing.B) {
	b.StopTimer()
	b.SetBytes(2)
	b.ReportAllocs()
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)

	var testdata [][]byte
	for _, v := range g_SipHeaderInfos {
		if v != nil {
			name := []byte(fmt.Sprintf("%s: ", string(v.name)))
			testdata = append(testdata, name)
		}
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		for _, v := range testdata {
			context.allocator.FreeAll()
			context.SetParseSrc(v)
			context.SetParsePos(0)
			ParseHeaderName(context)
		}
	}
}

package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipStartLineParse(t *testing.T) {
	testdata := []struct {
		src       string
		ok        bool
		isRequest bool
		newPos    int
		encode    string
	}{
		{"INVITE sip:123@a.com SIP/2.0\r\n", true, true, len("INVITE sip:123@a.com SIP/2.0\r\n"), "INVITE sip:123@a.com SIP/2.0\r\n"},
		{"SIP/2.0 200 OK\r\n", true, false, len("SIP/2.0 200 OK\r\n"), "SIP/2.0 200 OK\r\n"},
		{"SIP/2.0 200 OK xx\r\n", true, false, len("SIP/2.0 200 OK xx\r\n"), "SIP/2.0 200 OK xx\r\n"},
		{"SIP/2.0 200 \r\n", true, false, len("SIP/2.0 200 \r\n"), "SIP/2.0 200 \r\n"},
		{"SIP/2.0 200 %23\r\n", true, false, len("SIP/2.0 200 %23\r\n"), "SIP/2.0 200 %23\r\n"},

		{" INVITE sip:123@a.com SIP/2.0\r\n", false, true, 0, ""},
		{"INVITE", false, true, len("INVITE"), ""},
		{"INVITE@ sip:123@a.com SIP/2.0\r\n", false, true, len("INVITE"), ""},
		{"INVITE sip: SIP/2.0\r\n", false, true, len("INVITE sip:"), ""},
		{"INVITE sip:123@a.com", false, true, len("INVITE sip:123@a.com"), ""},
		{"INVITE sip:123@a.com@ SIP/2.0\r\n", false, true, len("INVITE sip:123@a.com"), ""},
		{"INVITE sip:123@a.com pSIP/2.0\r\n", false, true, len("INVITE sip:123@a.com "), ""},
		{"INVITE sip:123@a.com SIP/2.0", false, true, len("INVITE sip:123@a.com SIP/2.0"), ""},
		{"INVITE sip:123@a.com SIP/2.0\n", false, true, len("INVITE sip:123@a.com SIP/2.0"), ""},
		{"INVITE sip:123@a.com SIP/2.0\r", false, true, len("INVITE sip:123@a.com SIP/2.0"), ""},
		{"INVITE sip:123@a.com SIP/2.0\rt", false, true, len("INVITE sip:123@a.com SIP/2.0"), ""},
		{"INVITE sip:123@a.com SIP/2.0t\n", false, true, len("INVITE sip:123@a.com SIP/2.0"), ""},

		{"pSIP/2.0 200 OK\r\n", false, true, len("pSIP"), ""},
		{"SIP/2.0", false, false, len("SIP/2.0"), ""},
		{"SIP/2.0&", false, false, len("SIP/2.0"), ""},
		{"SIP/2.0 ", false, false, len("SIP/2.0 "), ""},
		{"SIP/2.0 a", false, false, len("SIP/2.0 "), ""},
		{"SIP/2.0 123", false, false, len("SIP/2.0 123"), ""},
		{"SIP/2.0 12a", false, false, len("SIP/2.0 12"), ""},
		{"SIP/2.0 123 ", false, false, len("SIP/2.0 123 "), ""},
		{"SIP/2.0 123 X", false, false, len("SIP/2.0 123 X"), ""},
		{"SIP/2.0 123 X\r", false, false, len("SIP/2.0 123 X"), ""},
		{"SIP/2.0 123 X\n", false, false, len("SIP/2.0 123 X"), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipStartLine(context)
			startLine := addr.GetSipStartLine(context)

			ok := startLine.Parse(context)
			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}
			test.EXPECT_EQ(t, startLine.isRequest, v.isRequest, "")
			test.EXPECT_EQ(t, startLine.String(context), v.encode, "")
		})
	}
}

func BenchmarkSipRequestLineParse(b *testing.B) {
	b.StopTimer()
	v := []byte("INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipStartLine(context)
	startLine := addr.GetSipStartLine(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		startLine.Parse(context)
	}
	//fmt.Printf("startLine = %s\n", startLine.String())
	fmt.Printf("")
}

func BenchmarkSipRequestLineEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("INVITE sip:6135000@24.15.255.4 SIP/2.0\r\n")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipStartLine(context)
	startLine := addr.GetSipStartLine(context)
	startLine.Parse(context)
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
		startLine.Encode(context, buf)
	}

	//fmt.Println("startLine =", buf.String())
}

func BenchmarkSipStatusLineParse(b *testing.B) {
	b.StopTimer()
	v := []byte("SIP/2.0 200 OK\r\n")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipStartLine(context)
	startLine := addr.GetSipStartLine(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		startLine.Parse(context)
	}
	//fmt.Printf("startLine = %s\n", startLine.String())
	fmt.Printf("")
}

func BenchmarkSipStatusLineEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("SIP/2.0 200 OK\r\n")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipStartLine(context)
	startLine := addr.GetSipStartLine(context)
	startLine.Parse(context)
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
		startLine.Encode(context, buf)
	}

	//fmt.Println("startLine =", buf.String())
}

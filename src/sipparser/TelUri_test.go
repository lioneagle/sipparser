package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestTelUriParseOK(t *testing.T) {
	testdata := []struct {
		src                      string
		isGlobalNumber           bool
		number                   string
		phoneContext             string
		phoneContextIsDomainName bool
	}{
		{"tel:+861234", true, "+861234", "", false},
		{"tel:+86-12.(34)", true, "+861234", "", false},
		{"tel:861234;phone-context=+123", false, "861234", "+123", false},
		{"tel:861234;phone-context=+123", false, "861234", "+123", false},
		{"tel:861234;phone-context=a.com", false, "861234", "a.com", true},
		{"tel:86-1.2(34);phone-context=a.com", false, "861234", "a.com", true},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewTelUri(context)
			uri := addr.GetTelUri(context)

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.IsGlobalNumber, v.isGlobalNumber, "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(len(v.src)), "")

			number := uri.number.CString(context)
			test.EXPECT_EQ(t, number, v.number, "")

			conext := uri.context.GetUriParam(context).value.CString(context)
			test.EXPECT_EQ(t, conext, v.phoneContext, "")

			test.EXPECT_EQ(t, uri.ContextIsDomain, v.phoneContextIsDomainName, "")
		})
	}
}

func TestTelUriParseNOK(t *testing.T) {
	testdata := []struct {
		src    string
		newPos int
	}{
		//{"tel1:+86123", 0},
		//{"tel:+", len("tel:+")},
		//{"tel:", len("tel:")},
		{"tel:.-()", len("tel:.-()")},
		//{"tel:zz", len("tel:")},
		//{"tel:123;", len("tel:123;")},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewTelUri(context)
			uri := addr.GetTelUri(context)

			ok := uri.Parse(context)
			test.EXPECT_FALSE(t, ok, "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")
		})
	}
}

func TestTelUriEncode(t *testing.T) {
	testdata := []struct {
		src string
		dst string
	}{
		{"tel:+861234", "tel:+861234"},
		{"tel:+861234;phonex=+123", "tel:+861234;phonex=+123"},
		{"tel:861234;phone-context=+123", "tel:861234;phone-context=+123"},
		{"tel:861234;x1=5;y;phone-context=+1-2.3(56);zz", "tel:861234;phone-context=+12356;x1=5;y;zz"},
		{"tel:861234;x1=5;y;phone-context=abc.com;zz", "tel:861234;phone-context=abc.com;x1=5;y;zz"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)

			addr := NewTelUri(context)
			uri := addr.GetTelUri(context)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)
			context.ParseSetTelUriKnownParam = false

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.String(context), v.dst, "")

		})
	}
}

func BenchmarkTelUriParse1(b *testing.B) {
	b.StopTimer()
	//v := []byte("tel:861234;x1=5;y;phone-context=abc.com;zz")
	//v := []byte("tel:861234;x1=5;phone-context=abc.com;zz")
	v := []byte("tel:861234;x1=5;phone-context=abc.com")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetTelUriKnownParam = false
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		addr := NewTelUri(context)
		uri := addr.GetTelUri(context)
		uri.Parse(context)
	}
	//fmt.Printf("uri = %s\n", uri.String())
}

func BenchmarkTelUriParse2(b *testing.B) {
	b.StopTimer()
	//v := []byte("tel:861234;x1=5;y;phone-context=abc.com;zz")
	//v := []byte("tel:861234;x1=5;phone-context=abc.com;zz")
	v := []byte("tel:861234;x1=5;phone-context=abc.com")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetTelUriKnownParam = true
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		addr := NewTelUri(context)
		uri := addr.GetTelUri(context)
		uri.Parse(context)
	}
	//fmt.Printf("uri = %s\n", uri.String())
}

func BenchmarkTelUriEncode1(b *testing.B) {
	b.StopTimer()
	//v := []byte("tel:861234;x1=5;y;phone-context=abc.com;zz")
	v := []byte("tel:861234;x1=5;y;phone-context=abc.com")
	//v := []byte("tel:861234")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetTelUriKnownParam = false
	addr := NewTelUri(context)
	uri := addr.GetTelUri(context)
	uri.Parse(context)
	remain := context.allocator.Used()
	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}
}

func BenchmarkTelUriEncode2(b *testing.B) {
	b.StopTimer()
	//v := []byte("tel:861234;x1=5;y;phone-context=abc.com;zz")
	v := []byte("tel:861234;x1=5;y;phone-context=abc.com")
	//v := []byte("tel:861234")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetTelUriKnownParam = true
	addr := NewTelUri(context)
	uri := addr.GetTelUri(context)
	uri.Parse(context)
	remain := context.allocator.Used()
	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}
}

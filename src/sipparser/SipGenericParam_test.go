package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipGenericParamParse(t *testing.T) {
	testdata := []struct {
		src       string
		ok        bool
		valueType byte
		newPos    int
		encode    string
	}{
		{"a=[asas]", true, SIP_GENERIC_VALUE_TYPE_IPV6, len("a=[asas]"), "a=[asas]"},
		{"a=b", true, SIP_GENERIC_VALUE_TYPE_TOKEN, len("a=b"), "a=b"},
		{"a\r\n\t=\r\n\tb", true, SIP_GENERIC_VALUE_TYPE_TOKEN, len("a\r\n\t=\r\n\tb"), "a=b"},
		{"a\r\n =\r\n b", true, SIP_GENERIC_VALUE_TYPE_TOKEN, len("a\r\n =\r\n b"), "a=b"},
		{"a=\"b\"", true, SIP_GENERIC_VALUE_TYPE_QUOTED_STRING, len("a=\"b\""), "a=\"b\""},
		{"a=\r\n\t\"b\"", true, SIP_GENERIC_VALUE_TYPE_QUOTED_STRING, len("a=\r\n\t\"b\""), "a=\"b\""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipGenericParam(context)
			param := addr.GetSipGenericParam(context)

			ok := param.Parse(context)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			test.EXPECT_EQ(t, param.valueType, v.valueType, "")
			test.EXPECT_EQ(t, param.String(context), v.encode, "")
		})
	}
}

/*
func TestGenericParamSetValueToken(t *testing.T) {

	testdata := []struct {
		name   string
		value  string
		encode string
	}{
		{"tag", "asac", "tag=asac"},
		{"boundary", "assk2121", "boundary=assk2121"},
	}

	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	prefix := FuncName()

	for i, v := range testdata {
		addr := NewSipGenericParam(context)
		param := addr.GetSipGenericParam(context)
		param.SetNameAsString(context, v.name)
		param.SetValueToken(context, []byte(v.value))

		if v.encode != param.String(context) {
			t.Errorf("%s[%d] failed: encode = %s, wanted = %s\n", prefix, i, param.String(context), v.encode)
			continue
		}
	}
}
*/

func TestParseSipGenericParams(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{";a=b", true, len(";a=b"), ";a=b"},
		{";a=b;c", true, len(";a=b;c"), ";a=b;c"},
		{";a=b;c=d", true, len(";a=b;c=d"), ";a=b;c=d"},
		{";a=b\r\n\t;c=d", true, len(";a=b\r\n\t;c=d"), ";a=b;c=d"},
		{";a=b\r\n\t; c\r\n = d", true, len(";a=b\r\n\t; c\r\n = d"), ";a=b;c=d"},

		{";a=", false, len(";a="), ""},
		{";@=", false, len(";"), ""},
		{";a\r\n =", false, len(";a\r\n ="), ""},
		{";a=\"ac", false, len(";a=\"ac"), ""},
		{";a=@", false, len(";a="), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			params, ok := ParseSipGenericParams(context, ';', nil)

			if v.ok {
				test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())
			} else {
				test.ASSERT_FALSE(t, ok, "")
			}

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

			if !v.ok {
				return
			}

			buf := NewAbnfByteBuffer(nil)
			EncodeSipGenericParams(context, buf, params, ';', nil)

			test.EXPECT_EQ(t, buf.String(), v.encode, "")
		})
	}
}

func BenchmarkParseSipGenericParams(b *testing.B) {
	b.StopTimer()
	v := []byte(";transport=tcp;method=REGISTER")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)

	remain := context.allocator.Used()
	context.SetParseSrc(v)
	context.SetParsePos(0)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		context.SetParsePos(0)
		ParseSipGenericParams(context, ';', nil)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkEncodeSipGenericParams(b *testing.B) {
	b.StopTimer()
	v := []byte(";transport=tcp;method=REGISTER")
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	params, _ := ParseSipGenericParams(context, ';', nil)
	remain := context.allocator.Used()
	buf := NewAbnfByteBuffer(nil)
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		EncodeSipGenericParams(context, buf, params, ';', nil)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

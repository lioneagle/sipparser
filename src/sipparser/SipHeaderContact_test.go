package sipparser

import (
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHeaderContactParse(t *testing.T) {
	testdata := []struct {
		src    string
		ok     bool
		newPos int
		encode string
	}{
		{"Contact: *", true, len("Contact: *"), "Contact: *"},
		{"Contact: sip:abc@a.com;tag=1", true, len("Contact: sip:abc@a.com;tag=1"), "Contact: sip:abc@a.com;tag=1"},
		{"m: <sip:abc@a.com;user=ip>;tag=1", true, len("m: <sip:abc@a.com;user=ip>;tag=1"), "Contact: <sip:abc@a.com;user=ip>;tag=1"},
		{"cOntact: abc<sip:abc@a.com;user=ip>;tag=1", true, len("Contact: abc<sip:abc@a.com;user=ip>;tag=1"), "Contact: abc<sip:abc@a.com;user=ip>;tag=1"},
		//{"Contact: tel:+12358;tag=123", true, len("Contact: tel:+12358;tag=123"), "Contact: <tel:+12358>;tag=123"},

		{" Contact: <sip:abc@a.com>;tag=1", false, 0, "0"},
		{"Contact1: <sip:abc@a.com>;tag=1", false, 0, ""},
		{"Contact: ", false, len("Contact: "), ""},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)
			context.EncodeUriAsNameSpace = false

			addr := NewSipHeaderContact(context)
			header := addr.GetSipHeaderContact(context)

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

func BenchmarkSipHeaderContactParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: sip:6140000@24.15.255.101:5060")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

func BenchmarkSipHeaderContactEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: sip:6140000@24.15.255.101:5060")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

func BenchmarkSipHeaderContactWith2KnownParamsParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: <sip:6140000@24.15.255.101:5060>;expires=3600;q=0.1")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetSipContactKnownParam = true
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

func BenchmarkSipHeaderContactWith2UnknownParamsParse(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: <sip:6140000@24.15.255.101:5060>;expires=3600;q=0.1")
	//v := []byte("Contact: <sip:6140000@24.15.255.101:5060>")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetSipContactKnownParam = false
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

func BenchmarkSipHeaderContactWith2KnownParamsEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: <sip:6140000@24.15.255.101:5060>;expires=3600;q=0.1")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetSipContactKnownParam = true
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

func BenchmarkSipHeaderContactWith2UnknownParamsEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("Contact: <sip:6140000@24.15.255.101:5060>;expires=3600;q=0.1")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.ParseSetSipContactKnownParam = false
	addr := NewSipHeaderContact(context)
	header := addr.GetSipHeaderContact(context)
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

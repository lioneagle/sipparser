package sipparser

import (
	//"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipHostPortUnknownString(t *testing.T) {
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 2)

	addr := NewSipHostPort(context)
	host := addr.GetSipHostPort(context)

	str := host.String(context)
	test.EXPECT_EQ(t, str, "unknown host", "")
}

func TestSipHostPortIpv4String(t *testing.T) {
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 2)

	addr := NewSipHostPort(context)
	host := addr.GetSipHostPort(context)

	ipv4 := []byte{10, 1, 1, 1}

	ok := host.SetIpv4(context, ipv4)
	test.ASSERT_TRUE(t, ok, "")
	test.EXPECT_TRUE(t, host.IsIpv4(), "")

	str := host.String(context)
	test.EXPECT_EQ(t, str, "10.1.1.1", "")
}

func TestSipHostPortIpv6String(t *testing.T) {
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 2)

	addr := NewSipHostPort(context)
	host := addr.GetSipHostPort(context)

	ipv4 := net.IPv4(10, 1, 1, 1)

	ok := host.SetIpv6(context, ipv4.To16())
	test.ASSERT_TRUE(t, ok, "")
	test.EXPECT_TRUE(t, host.IsIpv6(), "")

	str := host.String(context)
	test.EXPECT_EQ(t, str, "[10.1.1.1]", "")
}

func TestSipHostPortHostnameString(t *testing.T) {
	context := NewContext()
	context.allocator = NewMemAllocator(1024 * 30)

	addr := NewSipHostPort(context)
	host := addr.GetSipHostPort(context)

	ok := host.SetHostname(context, []byte("abc.com"))
	test.ASSERT_TRUE(t, ok, "")
	test.EXPECT_TRUE(t, host.IsHostname(), "")

	if !host.IsHostname() {
		t.Errorf("TestSipHostHostnameString failed: host is not hostname\n")
	}

	str := host.String(context)
	test.EXPECT_EQ(t, str, "abc.com", "")
}

func TestSipHostPortParseHostOk(t *testing.T) {
	testdata := []struct {
		src    string
		str    string
		newPos int
		id     byte
	}{
		{"10.43.12.14", "10.43.12.14", len("10.43.12.14"), HOST_TYPE_IPV4},
		{"10.43.12.14!", "10.43.12.14", len("10.43.12.14"), HOST_TYPE_IPV4},
		{"10.43.12.14ab", "10.43.12.14ab", len("10.43.12.14ab"), HOST_TYPE_NAME},
		{"10.43.12.14.", "10.43.12.14.", len("10.43.12.14."), HOST_TYPE_NAME},
		{"10.43.12.14-", "10.43.12.14-", len("10.43.12.14-"), HOST_TYPE_NAME},
		{"10.43.ab", "10.43.ab", len("10.43.ab"), HOST_TYPE_NAME},
		{"10.43.1", "10.43.1", len("10.43.1"), HOST_TYPE_NAME},
		{"10.43!", "10.43", len("10.43"), HOST_TYPE_NAME},
		{"[1080:0:0:0:8:800:200C:417A]ab", "[1080::8:800:200c:417a]", len("[1080:0:0:0:8:800:200C:417A]"), HOST_TYPE_IPV6},

		{"ab-c.com", "ab-c.com", len("ab-c.com"), HOST_TYPE_NAME},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHostPort(context)
			host := addr.GetSipHostPort(context)

			ok := host.ParseHost(context)

			test.ASSERT_TRUE(t, ok, "err =", context.Errors.String())
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")
			test.EXPECT_EQ(t, host.id, v.id, "")

			str := host.String(context)
			test.EXPECT_EQ(t, str, v.str, "")
		})
	}
}

func TestSipHostPortParseHostNOk(t *testing.T) {
	testdata := []struct {
		src string
	}{
		{""},
		{"!10.43.12.14"},
		{"[12"},
		{"[12!]"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			context.allocator.FreeAll()
			addr := NewSipHostPort(context)
			host := addr.GetSipHostPort(context)

			ok := host.ParseHost(context)

			test.EXPECT_FALSE(t, ok, "")
		})
	}
}

func TestSipHostPortParseOk(t *testing.T) {
	testdata := []struct {
		src     string
		str     string
		newPos  int
		id      byte
		hasPort bool
		port    uint16
	}{
		{"10.43.12.14", "10.43.12.14", len("10.43.12.14"), HOST_TYPE_IPV4, false, 0},
		{"10.43.12.14!", "10.43.12.14", len("10.43.12.14"), HOST_TYPE_IPV4, false, 0},
		{"10.43.12.14:5000", "10.43.12.14:5000", len("10.43.12.14:5000"), HOST_TYPE_IPV4, true, 5000},
		{"10.43.1:65535", "10.43.1:65535", len("10.43.1:65535"), HOST_TYPE_NAME, true, 65535},
		{"[1080:0:0:0:8:800:200C:417A]:0ab", "[1080::8:800:200c:417a]:0", len("[1080:0:0:0:8:800:200C:417A]:0"), HOST_TYPE_IPV6, true, 0},
		{"[1080:0:0:0:8:800:200C:417A]", "[1080::8:800:200c:417a]", len("[1080:0:0:0:8:800:200C:417A]"), HOST_TYPE_IPV6, false, 0},
		{"ab-c.com:123", "ab-c.com:123", len("ab-c.com:123"), HOST_TYPE_NAME, true, 123},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHostPort(context)
			host := addr.GetSipHostPort(context)

			ok := host.Parse(context)

			test.ASSERT_TRUE(t, ok, "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")
			test.EXPECT_EQ(t, host.id, v.id, "")
			test.EXPECT_EQ(t, host.HasPort(), v.hasPort, "")
			if v.hasPort {
				test.EXPECT_EQ(t, host.GetPort(), v.port, "")
			}

			str := host.String(context)
			test.EXPECT_EQ(t, str, v.str, "")
		})
	}
}

func TestSipHostPortParseNOk(t *testing.T) {
	testdata := []struct {
		src string
	}{
		{""},
		{"!10.43.12.14"},
		{"[12"},
		{"[12!]"},
		{"abd:"},
		{"abc:123456"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipHostPort(context)
			host := addr.GetSipHostPort(context)

			ok := host.Parse(context)

			test.EXPECT_FALSE(t, ok, "")
			//fmt.Println(context.Errors.String())
		})
	}
}

func TestWriteByteAsString(t *testing.T) {
	testdata := []struct {
		val byte
		ret string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{99, "99"},
		{109, "109"},
		{255, "255"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			buf := NewAbnfByteBuffer(nil)
			WriteByteAsString(buf, v.val)

			test.EXPECT_EQ(t, buf.String(), v.ret, "")
		})
	}
}

func TestSipHostPortWriteIpv4AsString(t *testing.T) {
	testdata := []struct {
		ipv4 []byte
		ret  string
	}{
		{[]byte{255, 254, 253, 252}, "255.254.253.252"},
		{[]byte{255, 0, 0, 252}, "255.0.0.252"},
		{[]byte{0, 0, 0, 252}, "0.0.0.252"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewContext()
			context.allocator = NewMemAllocator(1024 * 2)

			addr := NewSipHostPort(context)
			host := addr.GetSipHostPort(context)
			host.SetIpv4(context, v.ipv4)

			buf := NewAbnfByteBuffer(nil)
			host.WriteIpv4AsString(context, buf)

			test.EXPECT_EQ(t, buf.String(), v.ret, "")
		})
	}
}

func BenchmarkWriteByteAsString1(b *testing.B) {
	b.StopTimer()
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		WriteByteAsString(buf, 255)
	}
}

func BenchmarkWriteByteAsString2(b *testing.B) {
	b.StopTimer()
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	//buf := NewAbnfByteBuffer(nil)
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		WriteByteAsString(buf, 0)
	}
}

func BenchmarkWriteByteUseFmt1(b *testing.B) {
	b.StopTimer()
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteString(fmt.Sprintf("%d", 255))
	}
}

func BenchmarkWriteByteUseFmt2(b *testing.B) {
	b.StopTimer()
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteString(fmt.Sprintf("%d", 0))
	}
}

func BenchmarkWriteIpv4String(b *testing.B) {
	b.StopTimer()
	ip := []byte{255, 255, 255, 255}
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteString(net.IP(ip).String())
	}
}

func BenchmarkWriteIpv4UseFmt(b *testing.B) {
	b.StopTimer()
	ip := []byte{255, 255, 255, 255}
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.WriteString(fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]))
	}
}

func BenchmarkWriteIpv4AsString(b *testing.B) {
	b.StopTimer()
	context := NewContext()
	context.allocator = NewMemAllocator(1024)
	ip := []byte{255, 255, 255, 255}
	host := &SipHostPort{id: HOST_TYPE_IPV4}
	host.SetIpv4(context, ip)
	buf := NewAbnfByteBuffer(make([]byte, 1024))
	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		host.WriteIpv4AsString(context, buf)
	}
}

func BenchmarkSipHostPortParseIpv4(b *testing.B) {
	b.StopTimer()
	context := NewContext()
	context.allocator = NewMemAllocator(1024)
	host := &SipHostPort{}
	src := []byte("255.255.255.255")
	context.SetParseSrc(src)

	b.SetBytes(2)
	b.ReportAllocs()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.FreeAll()
		context.SetParsePos(0)
		host.parseIpv4(context)
	}
}

package sipparser

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestSipUriParseOK(t *testing.T) {
	testdata := []struct {
		src       string
		user      string
		password  string
		hostport  string
		isSipsUri bool
	}{
		{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "123", "", "abc.com", false},
		{"Sip:123:tsdd@[1080::8:800:200c:417a]:5061", "123", "tsdd", "[1080::8:800:200c:417a]:5061", false},
		{"sip:123:@10.43.12.14", "123", "", "10.43.12.14", false},
		{"sip:123:@10.43.12.14;x1", "123", "", "10.43.12.14", false},
		{"sip:%23123%31:@10.43.12.14", "#1231", "", "10.43.12.14", false},

		{"sips:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "123", "", "abc.com", true},
		{"sips:123:tsdd@[1080::8:800:200c:417a]:5061", "123", "tsdd", "[1080::8:800:200c:417a]:5061", true},
		{"sips:123:@10.43.12.14", "123", "", "10.43.12.14", true},
		{"sips:%23123%31:@10.43.12.14", "#1231", "", "10.43.12.14", true},
		{"sip:abc@biloxi.com;transport=tcp;method=REGISTER", "abc", "", "biloxi.com", false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.IsSipsUri(), v.isSipsUri, "")
			test.EXPECT_EQ(t, context.parsePos, AbnfPos(len(v.src)), "")

			user := uri.user.CString(context)
			test.EXPECT_EQ(t, user, v.user, "")

			password := uri.password.CString(context)
			test.EXPECT_EQ(t, password, v.password, "")

			test.EXPECT_EQ(t, uri.hostport.String(context), v.hostport, "")
		})
	}
}

/*func TestSipUriParamsParseOK(t *testing.T) {
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	prefix := FuncName()

	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	src := "sip:123@abc.com;ttl=10;user%32=phone%31;a;b;c;d;e?xx=yy&x1=aa"

	_, err := uri.Parse(context, []byte(src), 0)
	if err != nil {
		t.Errorf("%s failed, err = %s\n", prefix, err.Error())
		return
	}

	testdata := []struct {
		name     string
		value    string
		hasValue bool
	}{
		{"Ttl", "10", true},
		{"UseR2", "phone1", true},
		{"A", "", false},
		{"b", "", false},
		{"c", "", false},
		{"D", "", false},
		{"E", "", false},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 2)

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)

			newPos, ok := uri.Parse(context, []byte(v.src), 0)
			test.ASSERT_TRUE(t, ok, "")

			test.EXPECT_EQ(t, uri.IsSipsUri(), v.isSipsUri, "")
			test.EXPECT_EQ(t, newPos, AbnfPos(len(v.src)), "")

			user := uri.user.CString()
			test.EXPECT_EQ(t, user, v.user, "")

			password := uri.password.CString()
			test.EXPECT_EQ(t, password, v.password, "")

			test.EXPECT_EQ(t, uri.hostport.String(), v.hostport, "")
		})
	}

	for i, v := range testdata {
		param, ok := uri.params.GetParam(context, v.name)
		if !ok {
			t.Errorf("%s[%d] failed: cannot get %s param\n", prefix, i, v.name)
			continue
		}

		if param.value.Exist() && !v.hasValue {
			t.Errorf("%s[%d] failed: should have no pvalue\n", prefix, i)
			continue
		}

		if !param.value.Exist() && v.hasValue {
			t.Errorf("%s[%d] failed: should have pvalue\n", prefix, i)
			continue
		}

		if param.value.Exist() && param.value.String(context) != v.value {
			t.Errorf("%s[%d] failed: pvalue = %s, wanted = %s\n", prefix, i, param.value.String(context), v.value)
			continue
		}

	}
}

func TestSipUriHeadersParseOK(t *testing.T) {
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	prefix := FuncName()

	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	src := "sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"

	_, err := uri.Parse(context, []byte(src), 0)
	if err != nil {
		t.Errorf("%s failed, err = %s\n", err.Error())
		return
	}

	testdata := []struct {
		name     string
		value    string
		hasValue bool
	}{
		{"XX", "yy", true},
		{"x1", "aa", true},
	}

	for i, v := range testdata {
		header, ok := uri.headers.GetHeader(context, v.name)
		if !ok {
			t.Errorf("%s[%d] failed: cannot get ttl param\n", prefix, i)
			continue
		}

		if header.value.Exist() && !v.hasValue {
			t.Errorf("%s[%d] failed: should have no pvalue\n", prefix, i)
			continue
		}

		if !header.value.Exist() && v.hasValue {
			t.Errorf("%s[%d] failed: should have pvalue\n", prefix, i)
			continue
		}

		if header.value.Exist() && header.value.String(context) != v.value {
			t.Errorf("%s[%d] failed: pvalue = %s, wanted = %s\n", prefix, i, header.value.String(context), v.value)
			continue
		}
	}
}*/

func TestSipUriParseNOK(t *testing.T) {

	testdata := []struct {
		src    string
		newPos int
	}{
		//{"sipx:@abc.com", len("sipx:")},
		{"sipx:@abc.com", 0},
		{"sip:@abc.com", len("sip:")},
		{"sip::asas@abc.com", len("sip:")},
		{"sip:#123@abc.com", len("sip:")},
		{"sip:123:2#@abc.com", len("sip:123:2")},
		{"sip:123:2@abc.com;;", len("sip:123:2@abc.com;")},
		{"sip:123:2@abc.com;", len("sip:123:2@abc.com;")},
		{"sip:123:2@abc.com;a=;", len("sip:123:2@abc.com;a=")},
		{"sip:123:2@abc.com;ttl=10?q", len("sip:123:2@abc.com;ttl=10?q")},
		{"sip:123:2@abc.com;a=b?", len("sip:123:2@abc.com;a=b?")},

		{"sip:123:2@abc.com;a=b?@", len("sip:123:2@abc.com;a=b?")},
		{"sip:123:2@abc.com;a=b?c", len("sip:123:2@abc.com;a=b?c")},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 4)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)

			ok := uri.Parse(context)
			test.ASSERT_FALSE(t, ok, "")

			test.EXPECT_EQ(t, context.parsePos, AbnfPos(v.newPos), "")

		})
	}
}

func TestSipUriEncode(t *testing.T) {

	testdata := []struct {
		src string
		dst string
	}{
		{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"},
		//{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;user=phone;ttl=10;a;b;c;d;e?xx=yy&x1=aa"},
		{"sip:123:tsdd@[1080::8:800:200c:417a]:5061", "sip:123:tsdd@[1080::8:800:200c:417a]:5061"},
		{"sip:123:@10.43.12.14", "sip:123:@10.43.12.14"},
		{"sip:123@10.43.12.14;method=INVITE", "sip:123@10.43.12.14;method=INVITE"},
		{"sip:%23123%31:@10.43.12.14", "sip:%231231:@10.43.12.14"},
		{"sip:abc@biloxi.com;transport=tcp;method=REGISTER", "sip:abc@biloxi.com;transport=tcp;method=REGISTER"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.String(context), v.dst, "")

		})
	}
}

func TestSipUriEncode2(t *testing.T) {

	testdata := []struct {
		src string
		dst string
	}{
		//{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"},
		{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;user=phone;ttl=10;a;b;c;d;e?xx=yy&x1=aa"},
		{"sip:123:tsdd@[1080::8:800:200c:417a]:5061", "sip:123:tsdd@[1080::8:800:200c:417a]:5061"},
		{"sip:123:@10.43.12.14", "sip:123:@10.43.12.14"},
		{"sip:123@10.43.12.14;method=INVITE", "sip:123@10.43.12.14;method=INVITE"},
		{"sip:%23123%31:@10.43.12.14", "sip:%231231:@10.43.12.14"},
		{"sip:abc@biloxi.com;transport=tcp;method=REGISTER", "sip:abc@biloxi.com;transport=tcp;method=REGISTER"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.ParseSetSipUriKnownParam = true

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.String(context), v.dst, "")

		})
	}
}

func TestSipUriEncode3(t *testing.T) {

	testdata := []struct {
		src string
		dst string
	}{
		//{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa"},
		{"sip:123@abc.com;ttl=10;user=phone;a;b;c;d;e?xx=yy&x1=aa", "sip:123@abc.com;user=phone;ttl=10;a;b;c;d;e?xx=yy&x1=aa"},
		{"sip:123:tsdd@[1080::8:800:200c:417a]:5061", "sip:123:tsdd@[1080::8:800:200c:417a]:5061"},
		{"sip:123:@10.43.12.14", "sip:123:@10.43.12.14"},
		{"sip:123@10.43.12.14;method=INVITE", "sip:123@10.43.12.14;method=INVITE"},
		{"sip:%23123%31:@10.43.12.14", "sip:#1231:@10.43.12.14"},
		{"sip:abc@biloxi.com;transport=tcp;method=REGISTER", "sip:abc@biloxi.com;transport=tcp;method=REGISTER"},
	}

	for i, v := range testdata {
		v := v

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			t.Parallel()

			context := NewParseContext()
			context.allocator = NewMemAllocator(1024 * 10)
			context.ParseSetSipUriKnownParam = true
			context.EncodeUriNoEscape = true

			addr := NewSipUri(context)
			uri := addr.GetSipUri(context)
			context.SetParseSrc([]byte(v.src))
			context.SetParsePos(0)

			ok := uri.Parse(context)
			test.ASSERT_TRUE(t, ok, "err = %s", context.Errors.String())

			test.EXPECT_EQ(t, uri.String(context), v.dst, "")

		})
	}
}

/*func TestSipUriEqual(t *testing.T) {
	testdata := []struct {
		uri1  string
		uri2  string
		equal bool
	}{
		{"sip:abc.com", "sip:abc.com", true},
		{"sip:123abc@abc.com", "sip:123abc@aBC.com", true},
		{"sip:%61lice@atlanta.com;transport=TCP", "sip:alice@AtLanTa.CoM;Transport=tcp", true},
		{"sip:carol@chicago.com", "sip:carol@chicago.com;newparam=5", true},
		{"sip:carol@chicago.com;security=on", "sip:carol@chicago.com;newparam=5", true},
		{"sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com", "sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com", true},
		{"sip:alice@atlanta.com?subject=project%20x&priority=urgent", "sip:alice@atlanta.com?priority=urgent&subject=project%20x", true},

		{"sip:123abc@abc.com", "sips:123abc@abc.com", false},                                  // different scheme
		{"SIP:ALICE@AtLanTa.CoM;Transport=udp", "sip:alice@AtLanTa.CoM;Transport=UDP", false}, //different usernames
		{"SIP:ALICE@AtLanTa.CoM;Transport=udp", "sip:AtLanTa.CoM;Transport=UDP", false},       //different usernames
		{"sip:bob@biloxi.com", "sip:bob@biloxi.com:5060", false},                              //can resolve to different ports
		{"sip:bob@biloxi.com", "sip:bob@biloxi.com:6000;transport=tcp", false},                //can resolve to different port and transports
		{"sip:abc.com;user=phone", "sip:abc.com;user=ip", false},                              //different param
		{"sip:abc.com;user=phone", "sip:abc.com", false},                                      //different param
		{"sip:abc.com;ttl=11", "sip:abc.com;ttl=10", false},                                   //different param
		{"sip:abc.com", "sip:abc.com;ttl=10", false},                                          //different param
		{"sip:abc.com", "sip:abc.com;method=INVITE", false},                                   //different param
		{"sip:carol@chicago.com", "sip:carol@chicago.com?Subject=next%20meeting", false},      //different header component
		{"sip:bob@phone21.boxesbybob.com", "sip:bob@192.0.2.4", false},                        //even though that's what phone21.boxesbybob.com resolves to
	}

	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	prefix := FuncName()

	for i, v := range testdata {
		addr1 := NewSipUri(context)
		addr2 := NewSipUri(context)
		uri1 := addr1.GetSipUri(context)
		uri2 := addr2.GetSipUri(context)

		_, err := uri1.Parse(context, []byte(v.uri1), 0)
		if err != nil {
			t.Errorf("%s[%d] failed: uri1 parse failed, err = %s\n", prefix, i, err.Error())
			continue
		}

		_, err = uri2.Parse(context, []byte(v.uri2), 0)
		if err != nil {
			t.Errorf("%s[%d] failed: uri2 parse failed, err = %s\n", prefix, i, err.Error())
			continue
		}

		if v.equal && !uri1.Equal(context, uri2) {
			t.Errorf("%s[%d] failed: should be equal, uri1 = %s, uri2 = %s\n", prefix, i, v.uri1, v.uri2)
			continue
		}

		if !v.equal && uri1.Equal(context, uri2) {
			t.Errorf("%s[%d] failed: should not be equal, uri1 = %s, uri2 = %s\n", prefix, i, v.uri1, v.uri2)
			continue
		}
	}
}

//*/

func BenchmarkSipUriParse1(b *testing.B) {
	b.StopTimer()
	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	//v := []byte("sip:biloxi.com")
	//v := []byte("sip:abc@biloxi.com;transport=tcp")
	//v := []byte("sip:abc@biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
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
		addr := NewSipUri(context)
		uri := addr.GetSipUri(context)
		uri.ParseWithoutInit(context)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipUriParse2(b *testing.B) {
	b.StopTimer()
	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	//v := []byte("sip:biloxi.com")
	//v := []byte("sip:abc@biloxi.com;transport=tcp")
	//v := []byte("sip:abc@biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.ParseSetSipUriKnownParam = true
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
		addr := NewSipUri(context)
		uri := addr.GetSipUri(context)
		uri.ParseWithoutInit(context)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipUriRegexp(b *testing.B) {
	b.StopTimer()
	reg := regexp.MustCompile(`(?i:sip:)([[:alnum:]-_\.!~\*'\(\)&=\+\$,;\?/%]+(:[:alnum:]-_\.!~\*'\(\)]*)?@)?[[:alnum:]\.]+`)
	//reg := regexp.MustCompile(`(?i:sip:)`)

	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	//v := []byte("sip:biloxi.com")
	//v := []byte("sip:abc@biloxi.com;transport=tcp")
	//v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	//v := []byte("sip:abc@biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	//v := "sip:"

	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	//fmt.Printf("%q\n", reg.FindAllString(v, -1))

	for i := 0; i < b.N; i++ {
		//reg := regexp.MustCompile(`(?i:sip:)([[:alnum:]-_\.!~\*'\(\)&=\+\$,;\?/%]+(:[:alnum:]-_\.!~\*'\(\)]*)?@)?[[:alnum:]\.]+`)
		//reg.FindAllString(v, -1)
		reg.Match(v)
	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

//*
func BenchmarkSipUriString1(b *testing.B) {
	b.StopTimer()
	//v := "sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com"
	//v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	//v := []byte("sip:abc@biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	uri.Parse(context)
	remain := context.allocator.Used()
	b.ReportAllocs()
	b.SetBytes(2)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.String(context)
	}
}

//*/

//*
func BenchmarkSipUriEncode1(b *testing.B) {
	b.StopTimer()
	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	uri.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()

	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	//buf := &bytes.Buffer{}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}
	//fmt.Println("uri =", uri.String(context))
}

func BenchmarkSipUriEncode2(b *testing.B) {
	b.StopTimer()
	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	context.ParseSetSipUriKnownParam = true
	uri.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()

	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	//buf := &bytes.Buffer{}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}

	//fmt.Println("uri =", uri.String(context))
}

func BenchmarkSipUriEncode3(b *testing.B) {
	b.StopTimer()
	//v := []byte("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com")
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	context.ParseSetSipUriKnownParam = true
	context.EncodeUriNoEscape = true
	uri.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()

	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	//buf := &bytes.Buffer{}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}

	//fmt.Println("uri =", uri.String(context))
}

func BenchmarkGetUriParamByName(b *testing.B) {
	b.StopTimer()
	v := []byte("transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	context.ParseSetSipUriKnownParam = false
	params, ok := ParseUriParams(context, &g_SipUriParamCharsetInfo)
	if !ok {
		fmt.Println("ParseUriParams failed")
		return
	}
	name := []byte("user")
	b.SetBytes(2)
	b.ReportAllocs()

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		param := GetUriParamByName(context, params, name)
		if param == nil {
			fmt.Println("GetUriParamByName failed")
			return
		}
	}
}

func BenchmarkSipUriWith4UnknownParamsParse(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.ParseSetSipUriKnownParam = false
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
		addr := NewSipUri(context)
		uri := addr.GetSipUri(context)
		uri.ParseWithoutInit(context)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipUriWith4KnownParamsParse(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.ParseSetSipUriKnownParam = true
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
		addr := NewSipUri(context)
		uri := addr.GetSipUri(context)
		uri.ParseWithoutInit(context)

	}
	//fmt.Printf("uri = %s\n", uri.String())
	fmt.Printf("")
}

func BenchmarkSipUriWith4UnknownParamsEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	context.ParseSetSipUriKnownParam = false
	uri.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()

	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	//buf := &bytes.Buffer{}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}

	//fmt.Println("uri =", uri.String(context))
}

func BenchmarkSipUriWith4KnownParamsEncode(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	context.ParseSetSipUriKnownParam = true
	uri.Parse(context)
	remain := context.allocator.Used()
	b.SetBytes(2)
	b.ReportAllocs()

	//buf := bytes.NewBuffer(make([]byte, 1024*1024))
	buf := &AbnfByteBuffer{}
	//buf := &bytes.Buffer{}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		context.allocator.ClearAllocNum()
		context.allocator.FreePart(remain)
		uri.Encode(context, buf)
	}

	//fmt.Println("uri =", uri.String(context))
}

func BenchmarkGetUriParamByIndex(b *testing.B) {
	b.StopTimer()
	v := []byte("sip:abc@biloxi.com;transport=tcp;method=REGISTER;lr;user=phone")
	context := NewParseContext()
	context.allocator = NewMemAllocator(1024 * 30)
	context.SetParseSrc(v)
	context.SetParsePos(0)
	addr := NewSipUri(context)
	uri := addr.GetSipUri(context)
	context.ParseSetSipUriKnownParam = true
	uri.Parse(context)
	b.SetBytes(2)
	b.ReportAllocs()

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		param := uri.knownParams.GetSipUriKnownParams(context).params[SIP_URI_KNOWN_PARAM_USER]
		if param == ABNF_PTR_NIL {
			fmt.Println("GetUriParamByIndex failed")
			return
		}
	}
}

//*/

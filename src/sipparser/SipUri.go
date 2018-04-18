package sipparser

import (
	//"fmt"
	"unsafe"

	//"github.com/lioneagle/goutil/src/chars"
)

var g_SipUriParamCharsetInfo = CharsetInfo{
	nameCharsetIndex:  ABNF_CHARSET_SIP_PNAME,
	valueCharsetIndex: ABNF_CHARSET_SIP_PVALUE,
	nameMask:          ABNF_CHARSET_MASK_SIP_PNAME,
	valueMask:         ABNF_CHARSET_MASK_SIP_PVALUE,
}

var g_SipUriHeaderCharsetInfo = CharsetInfo{
	nameCharsetIndex:  ABNF_CHARSET_SIP_HNAME,
	valueCharsetIndex: ABNF_CHARSET_SIP_HVALUE,
	nameMask:          ABNF_CHARSET_MASK_SIP_HNAME,
	valueMask:         ABNF_CHARSET_MASK_SIP_HVALUE,
}

type SipUriKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_URI_KNOWN_PARAM_USER      = 0
	SIP_URI_KNOWN_PARAM_TRANSPORT = 1
	SIP_URI_KNOWN_PARAM_LR        = 2
	SIP_URI_KNOWN_PARAM_METHOD    = 3
	SIP_URI_KNOWN_PARAM_MADDR     = 4
	SIP_URI_KNOWN_PARAM_TTL       = 5

	SIP_URI_KNOWN_PARAM_MAX_NUM = iota
)

var g_SipUriKnownParamInfo = []SipUriKnownParamInfo{
	{[]byte("user\000"), SIP_URI_KNOWN_PARAM_USER},
	{[]byte("transport\000"), SIP_URI_KNOWN_PARAM_TRANSPORT},
	{[]byte("lr\000"), SIP_URI_KNOWN_PARAM_LR},
	{[]byte("method\000"), SIP_URI_KNOWN_PARAM_METHOD},
	{[]byte("maddr\000"), SIP_URI_KNOWN_PARAM_MADDR},
	{[]byte("ttl\000"), SIP_URI_KNOWN_PARAM_TTL},
}

type SipUriKnownParams struct {
	params [SIP_URI_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipUriKnownParams() int {
	return int(unsafe.Sizeof(SipUriKnownParams{}))
}

func NewSipUriKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipUriKnownParams()))
}

type SipUri struct {
	isSecure bool
	user     AbnfPtr
	password AbnfPtr
	hostport SipHostPort
	params   AbnfPtr
	headers  AbnfPtr

	//knownParams [SIP_URI_PARAM_MAX_NUM]AbnfPtr
	knownParams AbnfPtr
}

func SizeofSipUri() int {
	return int(unsafe.Sizeof(SipUri{}))
}

func NewSipUri(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipUri()))
}

func (this *SipUri) Init() {
	ZeroMem(this.memAddr(), SizeofSipUri())
}

func (this *SipUri) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipUri) SetSipUri()      { this.isSecure = false }
func (this *SipUri) SetSipsUri()     { this.isSecure = true }
func (this *SipUri) IsSipUri() bool  { return !this.isSecure }
func (this *SipUri) IsSipsUri() bool { return this.isSecure }

func (this *SipUri) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipUri) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	this.encodeScheme(buf)

	if this.user != ABNF_PTR_NIL {
		this.user.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
		if this.password != ABNF_PTR_NIL {
			buf.WriteByte(':')
			this.password.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_PASSWORD, ABNF_CHARSET_MASK_SIP_PASSWORD)
		}
		buf.WriteByte('@')
	}

	this.hostport.Encode(context, buf)

	/*if this.userParam != ABNF_PTR_NIL {
		buf.WriteByte(';')
		param := this.userParam.GetSipUriParam(context)
		param.Encode(context, buf)
	}*/

	/*
		this.EncodeKnownParams(context, buf)

		if this.params != ABNF_PTR_NIL {
			buf.WriteByte(';')
			this.encodeParams(context, buf)
			//EncodeUriParams(context,buf,this.params,)
		} //*/

	if this.knownParams != ABNF_PTR_NIL {
		EncodeUriParamsEx(context, buf, this.params, &g_SipUriParamCharsetInfo, this)
	} else {
		EncodeUriParams(context, buf, this.params, &g_SipUriParamCharsetInfo)
	}

	if this.headers != ABNF_PTR_NIL {
		buf.WriteByte('?')
		//this.encodeHeaders(context, buf)
		EncodeUriHeaders(context, buf, this.headers, &g_SipUriHeaderCharsetInfo)
	}
}

func (this *SipUri) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipUriKnownParams(context)

	for i := 0; i < SIP_URI_KNOWN_PARAM_MAX_NUM; i++ {
		if knownParams.params[i] != ABNF_PTR_NIL {
			buf.WriteByte(';')
			param := knownParams.params[i].GetUriParam(context)
			param.Encode(context, buf, &g_SipUriParamCharsetInfo)
		}
	}
}

func (this *SipUri) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipUriKnownParam {
		return false
	}
	/*if name.CStringEqualNoCase(context, g_SipUriUserParamName) {
		this.knownParams[SIP_URI_PARAM_USER] = param
		return true
	}*/
	var knownParams *SipUriKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipUriKnownParams(context)
	}

	len1 := len(g_SipUriKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipUriKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipUriKnownParams(context)

			}
			knownParams = this.knownParams.GetSipUriKnownParams(context)
			knownParams.params[g_SipUriKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipUri) encodeScheme(buf *AbnfByteBuffer) {
	if this.isSecure {
		buf.WriteString("sips:")
	} else {
		buf.WriteString("sip:")
	}
}

/*func (this *SipUri) encodeParams(context *ParseContext, buf *AbnfByteBuffer) {
	param := this.params.GetSipUriParam(context)

	for {
		param.Encode(context, buf)
		if param.next == ABNF_PTR_NIL {
			return
		}
		buf.WriteByte(';')
		param = param.next.GetSipUriParam(context)
	}
}

func (this *SipUri) encodeHeaders(context *ParseContext, buf *AbnfByteBuffer) {
	header := this.headers.GetSipUriHeader(context)

	for {
		header.Encode(context, buf)
		if header.next == ABNF_PTR_NIL {
			return
		}
		buf.WriteByte('&')
		header = header.next.GetSipUriHeader(context)
	}
}*/

func (this *SipUri) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipUri) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.ParseScheme(context)
	if !ok {
		return false
	}

	return this.ParseAfterSchemeWithoutInit(context)
}

func (this *SipUri) ParseAfterScheme(context *ParseContext) (ok bool) {
	return this.ParseAfterSchemeWithoutInit(context)
}

func (this *SipUri) ParseAfterSchemeWithoutInit(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(src))
	ok = this.parseUserinfo(context)
	if !ok {
		context.AddError(context.parsePos, "parse user-info failed")
		return false
	}

	ok = this.hostport.ParseWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse hostport failed")
		return false
	}

	if context.parsePos >= len1 {
		return true
	}

	if context.parseSrc[context.parsePos] == ';' {
		context.parsePos++
		//ok = this.parseParams(context)
		//this.params, ok = ParseUriParams(context, &g_SipUriParamCharsetInfo)
		this.params, ok = ParseUriParamsEx(context, &g_SipUriParamCharsetInfo, this)
		if !ok {
			context.AddError(context.parsePos, "parse sip uri params failed")
			return false
		}
	}

	if context.parsePos >= len1 {
		return true
	}

	if context.parseSrc[context.parsePos] == '?' {
		context.parsePos++
		//ok = this.parseHeaders(context)
		this.headers, ok = ParseUriHeaders(context, &g_SipUriHeaderCharsetInfo)
		if !ok {
			context.AddError(context.parsePos, "parse sip uri headers failed")
			return false
		}
	}

	return true
}

func (this *SipUri) ParseAfterSchemeWithoutParam(context *ParseContext) (ok bool) {
	//newPos = pos
	//this.Init()

	ok = this.parseUserinfo(context)
	if !ok {
		return false
	}

	ok = this.hostport.ParseWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse hostport failed")
		return false
	}
	return true
}

func (this *SipUri) parseUserinfo(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	hasUserinfo := findUserinfo(context.parseSrc, context.parsePos)
	if hasUserinfo {
		var user AbnfPtr

		user, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
		if !ok {
			context.AddError(context.parsePos, "parse user failed")
			return false
		}

		if context.parsePos >= len1 {
			context.AddError(context.parsePos, "reach end after user")
			return false
		}

		this.user = user

		ok = this.parsePassword(context)
		if !ok {
			context.AddError(context.parsePos, "parse password failed")
			return false
		}

		if context.parsePos >= len1 {
			context.AddError(context.parsePos, "reach end after password, and no '@'")
			return false
		}

		if context.parseSrc[context.parsePos] != '@' {
			context.AddError(context.parsePos, "no '@' after password")
			return false
		}

		context.parsePos++
	}

	return true
}

func (this *SipUri) parsePassword(context *ParseContext) (ok bool) {
	src := context.parseSrc

	if src[context.parsePos] == ':' {
		context.parsePos++
		if context.parsePos >= AbnfPos(len(src)) {
			context.AddError(context.parsePos, "reach end after ':' for password")
			return false
		}

		var password AbnfPtr

		password, ok = context.allocator.ParseAndAllocCStringEscapableEnableEmpty(context, ABNF_CHARSET_SIP_PASSWORD, ABNF_CHARSET_MASK_SIP_PASSWORD)
		if !ok {
			context.AddError(context.parsePos, "parse password value failed")
			return false
		}
		this.password = password
	}

	return true
}

func findUserinfo(src []byte, pos AbnfPos) bool {
	for _, v := range src[pos:] {
		if v == '@' {
			return true
		} else if v == '>' || IsLwsChar(v) {
			return false
		}
	}
	return false
}

//var g_SipUriUserParamName = []byte("user\000")

/*func (this *SipUri) parseParams(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for sip uri params")
		return false
	}

	var prev *SipUriParam = nil

	for context.parsePos < len1 {
		addr := NewSipUriParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for sip uri param")
			return false
		}
		param := addr.GetSipUriParam(context)
		ok = param.Parse(context)
		if !ok {
			return false
		}

		//str := param.name.GetCStringAsByteSlice(context)
		//if chars.EqualNoCase(str, g_SipUriUserAParamName) {
		//if param.name.CStringEqualNoCase(context, g_SipUriUserAParamName) {
		//	this.userParam = addr
		//} else {
		if !this.SetKnownParams(context, param.name, addr) {
			if prev != nil {
				prev.next = addr
			} else {
				this.params = addr
			}
			prev = param
		}

		if context.parsePos >= len1 {
			break
		}

		if context.parseSrc[context.parsePos] != ';' {
			break
		}
		context.parsePos++
	}

	return true
}
*/

/*func (this *SipUri) parseHeaders(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after '?' for sip uri headers")
		return false
	}

	var prev *SipUriHeader = nil

	for context.parsePos < len1 {
		addr := NewSipUriHeader(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for sip uri header")
			return false
		}
		header := addr.GetSipUriHeader(context)
		ok = header.Parse(context)
		if !ok {
			return false
		}

		if prev != nil {
			prev.next = addr
		} else {
			this.headers = addr
		}
		prev = header

		if context.parsePos >= len1 {
			break
		}

		if context.parseSrc[context.parsePos] != '&' {
			break
		}
		context.parsePos++
	}

	return true
}*/

func (this *SipUri) ParseScheme(context *ParseContext) (ok bool) {
	src1 := context.parseSrc[context.parsePos:]
	if hasSipPrefixNoCase(src1) {
		this.SetSipUri()
		context.parsePos += 4
		return true
	}

	if hasSipsPrefixNoCase(src1) {
		this.SetSipsUri()
		context.parsePos += 5
		return true
	}

	context.AddError(context.parsePos, "not sip-uri nor sips-uri")
	return false
}

func hasSipPrefixNoCase(src []byte) bool {
	return len(src) >= 4 && ((src[0] | 0x20) == 's') && ((src[1] | 0x20) == 'i') && ((src[2] | 0x20) == 'p') && (src[3] == ':')
}

func hasSipsPrefixNoCase(src []byte) bool {
	return len(src) >= 5 && ((src[0] | 0x20) == 's') && ((src[1] | 0x20) == 'i') && ((src[2] | 0x20) == 'p') &&
		((src[3] | 0x20) == 's') && (src[4] == ':')
}

/*type SipUriParam struct {
	name  AbnfPtr
	value AbnfPtr
	next  AbnfPtr
}

func SizeofSipUriParam() int {
	return int(unsafe.Sizeof(SipUriParam{}))
}

func NewSipUriParam(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipUriParam()))
}

func (this *SipUriParam) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	if this.name != ABNF_PTR_NIL {
		this.name.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_PNAME, ABNF_CHARSET_MASK_SIP_PNAME)

		if this.value != ABNF_PTR_NIL {
			buf.WriteByte('=')
			this.value.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_PVALUE, ABNF_CHARSET_MASK_SIP_PVALUE)
		}
	}
}

func (this *SipUriParam) Parse(context *ParseContext) (ok bool) {
	var name AbnfPtr
	var value AbnfPtr

	src := context.parseSrc
	len1 := AbnfPos(len(src))
	name, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_PNAME, ABNF_CHARSET_MASK_SIP_PNAME)
	if !ok {
		context.AddError(context.parsePos, "parse sip pname failed")
		return false
	}

	this.name = name

	if context.parsePos >= len1 {
		return true
	}

	if src[context.parsePos] == '=' {
		context.parsePos++
		value, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_PVALUE, ABNF_CHARSET_MASK_SIP_PVALUE)
		if !ok {
			context.AddError(context.parsePos, "parse sip pvalue failed")
			return false
		}
		this.value = value
	}

	return true
}*/

/*type SipUriHeader struct {
	name  AbnfPtr
	value AbnfPtr
	next  AbnfPtr
}

func SizeofSipUriHeader() int {
	return int(unsafe.Sizeof(SipUriHeader{}))
}

func NewSipUriHeader(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipUriHeader()))
}

func (this *SipUriHeader) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	if this.name != ABNF_PTR_NIL {
		this.name.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_HNAME, ABNF_CHARSET_MASK_SIP_HNAME)

		if this.value != ABNF_PTR_NIL {
			buf.WriteByte('=')
			this.value.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_HVALUE, ABNF_CHARSET_MASK_SIP_HVALUE)
		}
	}
}

func (this *SipUriHeader) Parse(context *ParseContext) (ok bool) {
	var name AbnfPtr
	var value AbnfPtr

	src := context.parseSrc
	len1 := AbnfPos(len(src))
	name, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_HNAME, ABNF_CHARSET_MASK_SIP_HNAME)
	if !ok {
		context.AddError(context.parsePos, "parse sip pname failed")
		return false
	}

	this.name = name

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after hname")
		return false
	}

	if src[context.parsePos] != '=' {
		context.AddError(context.parsePos, "no '=' after hname")
		return false
	}

	context.parsePos++

	if context.parsePos >= len1 {
		return true
	}

	value, ok = context.allocator.ParseAndAllocCStringEscapableEnableEmpty(context, ABNF_CHARSET_SIP_HVALUE, ABNF_CHARSET_MASK_SIP_HVALUE)
	if !ok {
		context.AddError(context.parsePos, "parse sip pvalue failed")
		return false
	}
	this.value = value

	return true
}*/
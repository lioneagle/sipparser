package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipViaKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_VIA_KNOWN_PARAM_BRANCH   = 0
	SIP_VIA_KNOWN_PARAM_RECEIVED = 1
	SIP_VIA_KNOWN_PARAM_RPORT    = 2
	SIP_VIA_KNOWN_PARAM_TTL      = 3
	SIP_VIA_KNOWN_PARAM_MADDR    = 4
	SIP_VIA_KNOWN_PARAM_MAX_NUM  = iota
)

var g_SipViaKnownParamInfo = []SipToKnownParamInfo{
	{[]byte("branch"), SIP_VIA_KNOWN_PARAM_BRANCH},
	{[]byte("received"), SIP_VIA_KNOWN_PARAM_RECEIVED},
	{[]byte("rport"), SIP_VIA_KNOWN_PARAM_RPORT},
	{[]byte("ttl"), SIP_VIA_KNOWN_PARAM_TTL},
	{[]byte("maddr"), SIP_VIA_KNOWN_PARAM_MADDR},
}

type SipViaKnownParams struct {
	params [SIP_VIA_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipViaKnownParams() int {
	return int(unsafe.Sizeof(SipViaKnownParams{}))
}

func NewSipViaKnownParams(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipViaKnownParams()))
}

type SipSentProtocol struct {
	name    AbnfPtr
	version AbnfPtr
}

func SizeofSipSentProtocol() int {
	return int(unsafe.Sizeof(SipSentProtocol{}))
}

func NewSipSentProtocol(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipSentProtocol()))
}

type SipHeaderVia struct {
	sentProtocol AbnfPtr
	transport    AbnfPtr
	sentBy       SipHostPort
	params       AbnfPtr
	knownParams  AbnfPtr
	next         AbnfPtr
}

func SizeofSipHeaderVia() int {
	return int(unsafe.Sizeof(SipHeaderVia{}))
}

func NewSipHeaderVia(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderVia()))
}

func (this *SipHeaderVia) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderVia) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderTo())
}

func (this *SipHeaderVia) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderVia) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Via: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderVia) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	if !this.sentProtocol.IsAbnfPtr() {
		buf.WriteString("SIP/2.0/")
	} else {
		sentProtocol := this.sentProtocol.GetSipSentProtocol(context)
		sentProtocol.name.WriteCString(context, buf)
		buf.WriteByte('/')
		sentProtocol.version.WriteCString(context, buf)
		buf.WriteByte('/')
	}
	this.transport.WriteCString(context, buf)
	buf.WriteByte(' ')
	this.sentBy.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Via               =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
 * via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / via-extension
 * via-ttl           =  "ttl" EQUAL ttl
 * via-maddr         =  "maddr" EQUAL host
 * via-received      =  "received" EQUAL (IPv4address / IPv6address)
 * via-branch        =  "branch" EQUAL token
 * via-extension     =  generic-param
 * sent-protocol     =  protocol-name SLASH protocol-version
 *                      SLASH transport
 * protocol-name     =  "SIP" / token
 * protocol-version  =  token
 * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
 *                      / other-transport
 * other-transport   =  token
 * sent-by           =  host [ COLON port ]
 * ttl               =  1*3DIGIT ; 0 to 255
 *
 * RFC3581
 *
 * response-port     = "rport" [EQUAL 1*DIGIT]
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / response-port / via-extension
 *
 */
func (this *SipHeaderVia) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderVia) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Via header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Via header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderVia) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderVia) ParseValueWithoutInit(context *Context) (ok bool) {
	if !this.parseSentProtocol(context) {
		context.AddError(context.parsePos, "parse sent-protocol failed for Via header")
		return false
	}

	this.transport, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "wrong transport for Via header")
		return false
	}

	if !ParseLWS(context) {
		context.AddError(context.parsePos, "wrong LWS after transport for Via header")
		return false
	}

	if !this.sentBy.ParseWithoutInit(context) {
		context.AddError(context.parsePos, "wrong sent-by for Via header")
		return false
	}

	if context.ParseSetSipViaKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Via header")
		return false
	}

	return true
}

func (this *SipHeaderVia) parseSentProtocol(context *Context) (ok bool) {
	if ((context.parsePos+6) < AbnfPos(len(context.parseSrc)) &&
		(context.parseSrc[context.parsePos]|0x20) == 's') &&
		((context.parseSrc[context.parsePos+1] | 0x20) == 'i') &&
		((context.parseSrc[context.parsePos+2] | 0x20) == 'p') &&
		(context.parseSrc[context.parsePos+3] == '/') &&
		(context.parseSrc[context.parsePos+4] == '2') &&
		(context.parseSrc[context.parsePos+5] == '.') &&
		(context.parseSrc[context.parsePos+6] == '0') {

		if ((context.parsePos + 7) < AbnfPos(len(context.parseSrc))) &&
			!IsDigit(context.parseSrc[context.parsePos+7]) {
			context.parsePos += 7
			if !ParseSWSMark(context, '/') {
				context.AddError(context.parsePos, "wrong SLASH after protocol-version for Via header")
				return false
			}

			this.sentProtocol = AbnfPtrSetValue(AbnfPtr(SIP_VERSION_2_0))
			return true
		}
	}

	this.sentProtocol = NewSipSentProtocol(context)
	if this.sentProtocol == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for sent-protocol for Via header")
		return false
	}

	sentProtocol := this.sentProtocol.GetSipSentProtocol(context)

	sentProtocol.name, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "wrong protocol-name for Via header")
		return false
	}

	if !ParseSWSMark(context, '/') {
		context.AddError(context.parsePos, "wrong SLASH after protocol-name for Via header")
		return false
	}

	sentProtocol.version, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "wrong protocol-version for Via header")
		return false
	}

	if !ParseSWSMark(context, '/') {
		context.AddError(context.parsePos, "wrong SLASH after protocol-version for Via header")
		return false
	}

	return true
}

func (this *SipHeaderVia) EncodeKnownParams(context *Context, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipViaKnownParams(context)

	for i := 0; i < SIP_VIA_KNOWN_PARAM_MAX_NUM; i++ {
		param := knownParams.params[i]
		if param != ABNF_PTR_NIL {
			buf.WriteByte(';')
			buf.Write(g_SipViaKnownParamInfo[i].name)
			param.GetSipGenericParam(context).EncodeValue(context, buf)
		}
	}
}

func (this *SipHeaderVia) SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipViaKnownParam {
		return false
	}

	var knownParams *SipViaKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.knownParams.GetSipViaKnownParams(context)
	}

	len1 := len(g_SipViaKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipViaKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipViaKnownParams(context)
				knownParams = this.knownParams.GetSipViaKnownParams(context)
			}

			knownParams.params[g_SipViaKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderVia) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'v' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}

		if (pos + 2) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'i') &&
			(src[pos+1]|0x20) == 'a' {
			if src[pos+2] == ':' || IsWspChar(src[pos+2]) {
				context.parsePos = pos + 2
				return true
			}
		}
	}

	return false
}

func ParseSipVia(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderVia(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Via header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderVia(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipViaValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderVia(context).EncodeValue(context, buf)
}

func AppendSipViaValue(context *Context, parsed AbnfPtr, header AbnfPtr) {
	for addr := parsed; addr != ABNF_PTR_NIL; {
		h := addr.GetSipHeaderVia(context)
		if h.next == ABNF_PTR_NIL {
			h.next = header
			return
		}
		addr = h.next
	}
}

func GetNextViaValue(context *Context, parsed AbnfPtr) AbnfPtr {
	return parsed.GetSipHeaderVia(context).next
}

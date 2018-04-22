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
	{[]byte("branch\000"), SIP_VIA_KNOWN_PARAM_BRANCH},
	{[]byte("received\000"), SIP_VIA_KNOWN_PARAM_RECEIVED},
	{[]byte("rport\000"), SIP_VIA_KNOWN_PARAM_RPORT},
	{[]byte("ttl\000"), SIP_VIA_KNOWN_PARAM_TTL},
	{[]byte("maddr\000"), SIP_VIA_KNOWN_PARAM_MADDR},
}

type SipViaKnownParams struct {
	params [SIP_VIA_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipViaKnownParams() int {
	return int(unsafe.Sizeof(SipToKnownParams{}))
}

func NewSipViaKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipViaKnownParams()))
}

type SipHeaderVia struct {
	protocolName    AbnfPtr
	protocolVersion AbnfPtr
	transport       AbnfPtr
	sentBy          SipHostPort
	params          AbnfPtr
	knownParams     AbnfPtr
	next            AbnfPtr
}

func SizeofSipHeaderVia() int {
	return int(unsafe.Sizeof(SipHeaderVia{}))
}

func NewSipHeaderVia(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderVia()))
}

func (this *SipHeaderVia) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderVia) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderTo())
}

func (this *SipHeaderVia) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderVia) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Via: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderVia) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	this.protocolName.WriteCString(context, buf)
	buf.WriteByte('/')
	this.protocolVersion.WriteCString(context, buf)
	buf.WriteByte('/')
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
func (this *SipHeaderVia) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderVia) ParseWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderVia) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderVia) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	this.protocolName, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "wrong protocol-name for Via header")
		return false
	}

	if !ParseSWSMark(context, '/') {
		context.AddError(context.parsePos, "wrong SLASH after protocol-name for Via header")
		return false
	}

	this.protocolVersion, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "wrong protocol-version for Via header")
		return false
	}

	if !ParseSWSMark(context, '/') {
		context.AddError(context.parsePos, "wrong SLASH after protocol-version for Via header")
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

func (this *SipHeaderVia) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipViaKnownParams(context)

	for i := 0; i < SIP_VIA_KNOWN_PARAM_MAX_NUM; i++ {
		if knownParams.params[i] != ABNF_PTR_NIL {
			buf.WriteByte(';')
			param := knownParams.params[i].GetSipGenericParam(context)
			param.Encode(context, buf)
		}
	}
}

func (this *SipHeaderVia) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipToKnownParam {
		return false
	}

	var knownParams *SipViaKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipViaKnownParams(context)
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

func (this *SipHeaderVia) parseHeaderName(context *ParseContext) (ok bool) {
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

func ParseSipVia(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderTo(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Via header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderTo(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipViaValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderTo(context).EncodeValue(context, buf)
}

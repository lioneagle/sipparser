package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipContentTypeKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_CONTENT_TYPE_KNOWN_PARAM_BOUNDARY = 0
	SIP_CONTENT_TYPE_KNOWN_PARAM_MAX_NUM  = iota
)

var g_SipContentTypeKnownParamInfo = []SipContentTypeKnownParamInfo{
	{[]byte("boundary\000"), SIP_CONTENT_TYPE_KNOWN_PARAM_BOUNDARY},
}

type SipContentTypeKnownParams struct {
	params [SIP_CONTENT_TYPE_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipContentTypeKnownParams() int {
	return int(unsafe.Sizeof(SipContentTypeKnownParams{}))
}

func NewSipContentTypeKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipContentTypeKnownParams()))
}

type SipHeaderContentType struct {
	mainType    AbnfPtr
	subType     AbnfPtr
	params      AbnfPtr
	knownParams AbnfPtr
}

func SizeofSipHeaderContentType() int {
	return int(unsafe.Sizeof(SipHeaderContentType{}))
}

func NewSipHeaderContentType(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderContentType()))
}

func (this *SipHeaderContentType) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderContentType) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderContentType())
}

func (this *SipHeaderContentType) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderContentType) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Content-Type: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderContentType) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	this.mainType.WriteCString(context, buf)
	buf.WriteByte('/')
	this.subType.WriteCString(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
 * media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
 * m-type           =  discrete-type / composite-type
 * discrete-type    =  "text" / "image" / "audio" / "video"
 *                     / "application" / extension-token
 * composite-type   =  "message" / "multipart" / extension-token
 * extension-token  =  ietf-token / x-token
 * ietf-token       =  token
 * x-token          =  "x-" token
 * m-subtype        =  extension-token / iana-token
 * iana-token       =  token
 * m-parameter      =  m-attribute EQUAL m-value
 * m-attribute      =  token
 * m-value          =  token / quoted-string
 */
func (this *SipHeaderContentType) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderContentType) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Content-Type header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Content-Type header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentType) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentType) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	this.mainType, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "parse m-type failed for Content-Type header")
		return false
	}

	if !ParseSWSMark(context, '/') {
		context.AddError(context.parsePos, "wrong SLASH after protocol-name for Content-Type header")
		return false
	}

	this.subType, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "parse m-subtype failed for Content-Type header")
		return false
	}

	if context.ParseSetSipFromKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Content-Type header")
		return false
	}

	return true
}

func (this *SipHeaderContentType) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipContentTypeKnownParams(context)

	for i := 0; i < SIP_CONTENT_TYPE_KNOWN_PARAM_MAX_NUM; i++ {
		param := knownParams.params[i]
		if param != ABNF_PTR_NIL {
			buf.WriteByte(';')
			buf.Write(g_SipContentTypeKnownParamInfo[i].name)
			param.GetSipGenericParam(context).EncodeValue(context, buf)
		}
	}
}

func (this *SipHeaderContentType) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipContentTypeKnownParam {
		return false
	}

	var knownParams *SipContentTypeKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipContentTypeKnownParams(context)
	}

	len1 := len(g_SipContentTypeKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipContentTypeKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipContentTypeKnownParams(context)
				knownParams = this.knownParams.GetSipContentTypeKnownParams(context)
			}

			knownParams.params[g_SipContentTypeKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderContentType) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'c' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}

		if (pos + 11) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'o') &&
			((src[pos+1] | 0x20) == 'n') &&
			((src[pos+2] | 0x20) == 't') &&
			((src[pos+3] | 0x20) == 'e') &&
			((src[pos+4] | 0x20) == 'n') &&
			((src[pos+5] | 0x20) == 't') &&
			(src[pos+6] == '-') &&
			((src[pos+7] | 0x20) == 't') &&
			((src[pos+8] | 0x20) == 'y') &&
			((src[pos+9] | 0x20) == 'p') &&
			((src[pos+10] | 0x20) == 'e') {
			if src[pos+11] == ':' || IsWspChar(src[pos+11]) {
				context.parsePos = pos + 11
				return true
			}
		}
	} else if src[pos]|0x20 == 'l' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}
	}

	return false
}

func ParseSipContentType(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderContentType(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Content-Type header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderContentType(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipContentTypeValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderContentType(context).EncodeValue(context, buf)
}

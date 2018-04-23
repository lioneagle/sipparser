package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipContentDispositionKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_CONTENT_DISPOSITION_KNOWN_PARAM_HANDLING = 0
	SIP_CONTENT_DISPOSITION_KNOWN_PARAM_MAX_NUM  = iota
)

var g_SipContentDispositionKnownParamInfo = []SipContentDispositionKnownParamInfo{
	{[]byte("handling\000"), SIP_CONTENT_TYPE_KNOWN_PARAM_BOUNDARY},
}

type SipContentDispositionKnownParams struct {
	params [SIP_CONTENT_DISPOSITION_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipContentDispositionKnownParams() int {
	return int(unsafe.Sizeof(SipContentDispositionKnownParams{}))
}

func NewSipContentDispositionKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipContentDispositionKnownParams()))
}

type SipHeaderContentDisposition struct {
	dispType    AbnfPtr
	params      AbnfPtr
	knownParams AbnfPtr
}

func SizeofSipHeaderContentDisposition() int {
	return int(unsafe.Sizeof(SipHeaderContentDisposition{}))
}

func NewSipHeaderContentDisposition(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderContentDisposition()))
}

func (this *SipHeaderContentDisposition) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderContentDisposition) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderContentDisposition())
}

func (this *SipHeaderContentDisposition) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderContentDisposition) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Content-Disposition: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderContentDisposition) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	this.dispType.WriteCString(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Content-Disposition   =  "Content-Disposition" HCOLON
 *                          disp-type *( SEMI disp-param )
 * disp-type             =  "render" / "session" / "icon" / "alert"
 *                          / disp-extension-token
 * disp-param            =  handling-param / generic-param
 * handling-param        =  "handling" EQUAL
 *                          ( "optional" / "required"
 *                          / other-handling )
 * other-handling        =  token
 * disp-extension-token  =  token
 *
 */
func (this *SipHeaderContentDisposition) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderContentDisposition) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Content-Disposition header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Content-Disposition header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentDisposition) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentDisposition) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	this.dispType, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "parse disp-type failed for Content-Disposition header")
		return false
	}

	if context.ParseSetSipFromKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Content-Disposition header")
		return false
	}

	return true
}

func (this *SipHeaderContentDisposition) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipContentDispositionKnownParams(context)

	for i := 0; i < SIP_CONTENT_DISPOSITION_KNOWN_PARAM_MAX_NUM; i++ {
		if knownParams.params[i] != ABNF_PTR_NIL {
			buf.WriteByte(';')
			param := knownParams.params[i].GetSipGenericParam(context)
			param.Encode(context, buf)
		}
	}
}

func (this *SipHeaderContentDisposition) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipContentDispositionKnownParam {
		return false
	}

	var knownParams *SipContentDispositionKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipContentDispositionKnownParams(context)
	}

	len1 := len(g_SipContentDispositionKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipContentDispositionKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipContentDispositionKnownParams(context)
				knownParams = this.knownParams.GetSipContentDispositionKnownParams(context)
			}

			knownParams.params[g_SipContentDispositionKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderContentDisposition) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'c' {
		pos++
		if (pos + 18) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'o') &&
			((src[pos+1] | 0x20) == 'n') &&
			((src[pos+2] | 0x20) == 't') &&
			((src[pos+3] | 0x20) == 'e') &&
			((src[pos+4] | 0x20) == 'n') &&
			((src[pos+5] | 0x20) == 't') &&
			(src[pos+6] == '-') &&
			((src[pos+7] | 0x20) == 'd') &&
			((src[pos+8] | 0x20) == 'i') &&
			((src[pos+9] | 0x20) == 's') &&
			((src[pos+10] | 0x20) == 'p') &&
			((src[pos+11] | 0x20) == 'o') &&
			((src[pos+12] | 0x20) == 's') &&
			((src[pos+13] | 0x20) == 'i') &&
			((src[pos+14] | 0x20) == 't') &&
			((src[pos+15] | 0x20) == 'i') &&
			((src[pos+16] | 0x20) == 'o') &&
			((src[pos+17] | 0x20) == 'n') {
			if src[pos+18] == ':' || IsWspChar(src[pos+18]) {
				context.parsePos = pos + 18
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

func ParseSipContentDisposition(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderContentType(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Content-Disposition header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderContentDisposition(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipContentDispositionValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderContentDisposition(context).EncodeValue(context, buf)
}

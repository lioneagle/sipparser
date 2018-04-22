package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipToKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_TO_KNOWN_PARAM_TAG     = 0
	SIP_TO_KNOWN_PARAM_MAX_NUM = iota
)

var g_SipToKnownParamInfo = []SipToKnownParamInfo{
	{[]byte("tag\000"), SIP_TO_KNOWN_PARAM_TAG},
}

type SipToKnownParams struct {
	params [SIP_TO_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipToKnownParams() int {
	return int(unsafe.Sizeof(SipToKnownParams{}))
}

func NewSipToKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipToKnownParams()))
}

type SipHeaderTo struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
}

func SizeofSipHeaderTo() int {
	return int(unsafe.Sizeof(SipHeaderTo{}))
}

func NewSipHeaderTo(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderTo()))
}

func (this *SipHeaderTo) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderTo) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderTo())
}

func (this *SipHeaderTo) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderTo) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("To: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderTo) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * To        =  ( "To" / "t" ) HCOLON ( name-addr
 *            / addr-spec ) *( SEMI to-param )
 * to-param  =  tag-param / generic-param
 */
func (this *SipHeaderTo) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderTo) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for To header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for To header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderTo) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderTo) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	ok = this.addr.ParseWithoutInit(context, false)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for To header")
		return false
	}

	if context.ParseSetSipToKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for To header")
		return false
	}

	return true
}

func (this *SipHeaderTo) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipToKnownParams(context)

	for i := 0; i < SIP_TO_KNOWN_PARAM_MAX_NUM; i++ {
		if knownParams.params[i] != ABNF_PTR_NIL {
			buf.WriteByte(';')
			param := knownParams.params[i].GetSipGenericParam(context)
			param.Encode(context, buf)
		}
	}
}

func (this *SipHeaderTo) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipToKnownParam {
		return false
	}

	var knownParams *SipToKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipToKnownParams(context)
	}

	len1 := len(g_SipToKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipToKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipToKnownParams(context)
				knownParams = this.knownParams.GetSipToKnownParams(context)
			}

			knownParams.params[g_SipToKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderTo) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 't' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}

		if (pos + 1) >= len1 {
			return false
		}

		if (src[pos] | 0x20) == 'o' {
			if src[pos+1] == ':' || IsWspChar(src[pos+1]) {
				context.parsePos = pos + 1
				return true
			}
		}
	}

	return false
}

func ParseSipTo(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderTo(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for To header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderTo(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipToValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderTo(context).EncodeValue(context, buf)
}

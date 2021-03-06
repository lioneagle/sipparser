package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipFromKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_FROM_KNOWN_PARAM_TAG     = 0
	SIP_FROM_KNOWN_PARAM_MAX_NUM = iota
)

var g_SipFromKnownParamInfo = []SipFromKnownParamInfo{
	{[]byte("tag"), SIP_FROM_KNOWN_PARAM_TAG},
}

type SipFromKnownParams struct {
	params [SIP_FROM_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipFromKnownParams() int {
	return int(unsafe.Sizeof(SipFromKnownParams{}))
}

func NewSipFromKnownParams(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipFromKnownParams()))
}

type SipHeaderFrom struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
}

func SizeofSipHeaderFrom() int {
	return int(unsafe.Sizeof(SipHeaderFrom{}))
}

func NewSipHeaderFrom(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderFrom()))
}

func (this *SipHeaderFrom) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderFrom) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderFrom())
}

func (this *SipHeaderFrom) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderFrom) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("From: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderFrom) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * From        =  ( "From" / "f" ) HCOLON from-spec
 * from-spec   =  ( name-addr / addr-spec )
 *                *( SEMI from-param )
 * from-param  =  tag-param / generic-param
 * tag-param   =  "tag" EQUAL token
 */
func (this *SipHeaderFrom) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderFrom) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for From header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for From header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderFrom) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderFrom) ParseValueWithoutInit(context *Context) (ok bool) {
	ok = this.addr.ParseWithoutInit(context, false)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for From header")
		return false
	}

	if context.ParseSetSipFromKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for From header")
		return false
	}

	return true
}

func (this *SipHeaderFrom) EncodeKnownParams(context *Context, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipFromKnownParams(context)

	for i := 0; i < SIP_FROM_KNOWN_PARAM_MAX_NUM; i++ {
		param := knownParams.params[i]
		if param != ABNF_PTR_NIL {
			buf.WriteByte(';')
			buf.Write(g_SipFromKnownParamInfo[i].name)
			param.GetSipGenericParam(context).EncodeValue(context, buf)
		}
	}
}

func (this *SipHeaderFrom) SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipFromKnownParam {
		return false
	}

	var knownParams *SipFromKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.knownParams.GetSipFromKnownParams(context)
	}

	len1 := len(g_SipFromKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipFromKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipFromKnownParams(context)
				knownParams = this.knownParams.GetSipFromKnownParams(context)
			}

			knownParams.params[g_SipFromKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderFrom) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'f' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}

		if (pos + 3) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'r') &&
			((src[pos+1] | 0x20) == 'o') &&
			((src[pos+2] | 0x20) == 'm') {
			if src[pos+3] == ':' || IsWspChar(src[pos+3]) {
				context.parsePos = pos + 3
				return true
			}
		}
	}

	return false
}

func ParseSipFrom(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderFrom(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for From header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderFrom(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipFromValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderFrom(context).EncodeValue(context, buf)
}

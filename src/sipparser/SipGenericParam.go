package sipparser

import (
	//"fmt"
	"unsafe"
)

type KnownSipGenericParams interface {
	SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool
	EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer)
}

const (
	SIP_GENERIC_VALUE_TYPE_TOKEN         = byte(0)
	SIP_GENERIC_VALUE_TYPE_QUOTED_STRING = byte(1)
	//SIP_GENERIC_VALUE_TYPE_HOST          = byte(2)
)

type SipGenericParam struct {
	name      AbnfPtr
	value     AbnfPtr
	next      AbnfPtr
	valueType byte
}

func SizeofSipGenericParam() int {
	return int(unsafe.Sizeof(SipGenericParam{}))
}

func NewSipGenericParam(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipGenericParam()))
}

func (this *SipGenericParam) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipGenericParam) Init() {
	ZeroMem(this.memAddr(), SizeofSipGenericParam())
}

func (this *SipGenericParam) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipGenericParam) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	if this.name != ABNF_PTR_NIL {
		this.name.WriteCString(context, buf)
		this.EncodeValue(context, buf)
	}
}

func (this *SipGenericParam) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	if this.value != ABNF_PTR_NIL {
		buf.WriteByte('=')
		if this.valueType == SIP_GENERIC_VALUE_TYPE_TOKEN {
			this.value.WriteCString(context, buf)
		} else if this.valueType == SIP_GENERIC_VALUE_TYPE_QUOTED_STRING {
			EncodeSipQuotedString(context, buf, this.value)
		}
	}
}

/*
 * generic-param  =  token [ EQUAL gen-value ]
 * gen-value      =  token / host / quoted-string
 *
 */
func (this *SipGenericParam) Parse(context *ParseContext) (ok bool) {
	this.name, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
	if !ok {
		context.AddError(context.parsePos, "parse generic-name failed")
		return false
	}

	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		return true
	}

	v := context.parseSrc[context.parsePos]

	if v != '=' && !IsLwsChar(v) {
		return true
	}

	ok = ParseSWSMark(context, '=')
	if !ok {
		return false
	}

	return this.ParseValue(context)
}

func (this *SipGenericParam) ParseValue(context *ParseContext) (ok bool) {
	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		context.AddError(context.parsePos, "empty gen-value")
		return false
	}

	/* @@TODO: 目前解gen-value时，暂不考虑解析出host，因为一般没有必要解析出来，以后再考虑添加这个功能 */
	v := context.parseSrc[context.parsePos]
	if IsSipToken(v) {
		//this.value, ok = context.allocator.ParseAndAllocCStringEscapable(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		this.value, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		if ok {
			this.valueType = SIP_GENERIC_VALUE_TYPE_TOKEN
		}
		return ok
	} else if (v == '"') || IsLwsChar(v) {
		this.value, ok = context.allocator.ParseAndAllocSipQuotedString(context)
		if ok {
			this.valueType = SIP_GENERIC_VALUE_TYPE_QUOTED_STRING
		}
		return ok
	}

	context.AddError(context.parsePos, "not token nor quoted-string for gen-value")
	return false
}

/* RFC3261
 *
 * generic-param-list   =  *( SWS seperator SWS generic-param )
 *
 * seperator is usually ';'
 *
 */
func ParseSipGenericParams(context *ParseContext, seperator byte, knownParams KnownSipGenericParams) (params AbnfPtr, ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		return ABNF_PTR_NIL, true
	}

	var prev *SipGenericParam = nil

	for context.parsePos < len1 {
		if IsOnlyCRLF(context.parseSrc, context.parsePos) {
			return params, true
		}

		if context.parseSrc[context.parsePos] != seperator && !IsLwsChar(context.parseSrc[context.parsePos]) {
			return params, true
		}

		var macthMark bool
		pos := context.parsePos
		macthMark, ok = ParseSWSMarkCanOmmit(context, seperator)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if !macthMark {
			context.parsePos = pos
			return params, true
		}

		addr := NewSipGenericParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for sip generic-param")
			return ABNF_PTR_NIL, false
		}
		param := addr.GetSipGenericParam(context)
		ok = param.Parse(context)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if (knownParams == nil) || !knownParams.SetKnownParams(context, param.name, addr) {
			if prev != nil {
				prev.next = addr
			} else {
				params = addr
			}
			prev = param
		}
	}

	return params, true
}

func EncodeSipGenericParams(context *ParseContext, buf *AbnfByteBuffer, params AbnfPtr, seperator byte, knownParams KnownSipGenericParams) {
	if knownParams != nil {
		knownParams.EncodeKnownParams(context, buf)
	}

	if params != ABNF_PTR_NIL {
		param := params.GetSipGenericParam(context)

		for {
			buf.WriteByte(seperator)
			param.Encode(context, buf)
			if param.next == ABNF_PTR_NIL {
				return
			}
			param = param.next.GetSipGenericParam(context)
		}
	}
}

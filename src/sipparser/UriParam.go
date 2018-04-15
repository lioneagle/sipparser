package sipparser

import (
	//"fmt"
	"unsafe"
)

type KnownUriParams interface {
	SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool
	EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer)
}

type UriParam struct {
	name  AbnfPtr
	value AbnfPtr
	next  AbnfPtr
}

type CharsetInfo struct {
	nameCharsetIndex  int
	valueCharsetIndex int
	nameMask          uint32
	valueMask         uint32
}

func SizeofUriParam() int {
	return int(unsafe.Sizeof(UriParam{}))
}

func NewUriParam(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofUriParam()))
}

func (this *UriParam) Encode(context *ParseContext, buf *AbnfByteBuffer, charsets *CharsetInfo) {

	if this.name != ABNF_PTR_NIL {
		this.name.WriteCStringEscape(context, buf, charsets.nameCharsetIndex, charsets.nameMask)

		if this.value != ABNF_PTR_NIL {
			buf.WriteByte('=')
			this.value.WriteCStringEscape(context, buf, charsets.valueCharsetIndex, charsets.valueMask)
		}
	}
}

func (this *UriParam) Parse(context *ParseContext, charsets *CharsetInfo) (ok bool) {

	var name AbnfPtr
	var value AbnfPtr

	src := context.parseSrc
	len1 := AbnfPos(len(src))
	name, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsets.nameCharsetIndex, charsets.nameMask)
	if !ok {
		context.AddError(context.parsePos, "parse uri pname failed")
		return false
	}

	this.name = name

	if context.parsePos >= len1 {
		return true
	}

	if src[context.parsePos] == '=' {
		context.parsePos++
		value, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsets.valueCharsetIndex, charsets.valueMask)
		if !ok {
			context.AddError(context.parsePos, "parse uri pvalue failed")
			return false
		}
		this.value = value
	}

	return true
}

func ParseUriParams(context *ParseContext, charsets *CharsetInfo) (params AbnfPtr, ok bool) {

	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for uri params")
		return ABNF_PTR_NIL, false
	}

	var prev *UriParam = nil

	for context.parsePos < len1 {
		addr := NewUriParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for uri param")
			return ABNF_PTR_NIL, false
		}
		param := addr.GetUriParam(context)
		ok = param.Parse(context, charsets)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if prev != nil {
			prev.next = addr
		} else {
			params = addr
		}
		prev = param

		if context.parsePos >= len1 {
			break
		}

		if context.parseSrc[context.parsePos] != ';' {
			break
		}
		context.parsePos++
	}

	return params, true
}

func ParseUriParamsEx(context *ParseContext, charsets *CharsetInfo, knownParams KnownUriParams) (params AbnfPtr, ok bool) {

	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for uri params")
		return ABNF_PTR_NIL, false
	}

	var prev *UriParam = nil

	for context.parsePos < len1 {
		addr := NewUriParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for uri param")
			return ABNF_PTR_NIL, false
		}
		param := addr.GetUriParam(context)
		ok = param.Parse(context, charsets)
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

		if context.parsePos >= len1 {
			return params, true
		}

		if context.parseSrc[context.parsePos] != ';' {
			return params, true
		}
		context.parsePos++
	}

	return params, true
}

func EncodeUriParams(context *ParseContext, buf *AbnfByteBuffer, params AbnfPtr, charsets *CharsetInfo) {
	if params != ABNF_PTR_NIL {
		param := params.GetUriParam(context)

		for {
			buf.WriteByte(';')
			param.Encode(context, buf, charsets)
			if param.next == ABNF_PTR_NIL {
				return
			}
			param = param.next.GetUriParam(context)
		}
	}
}

func EncodeUriParamsEx(context *ParseContext, buf *AbnfByteBuffer, params AbnfPtr, charsets *CharsetInfo, knownParams KnownUriParams) {
	if knownParams != nil {
		knownParams.EncodeKnownParams(context, buf)
	}

	if params != ABNF_PTR_NIL {
		param := params.GetUriParam(context)
		for {
			buf.WriteByte(';')
			param.Encode(context, buf, charsets)
			if param.next == ABNF_PTR_NIL {
				return
			}
			param = param.next.GetUriParam(context)
		}
	}
}

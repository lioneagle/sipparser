package sipparser

import (
	//"fmt"
	"unsafe"
)

type UriHeader struct {
	name  AbnfPtr
	value AbnfPtr
	next  AbnfPtr
}

func SizeofUriHeader() int {
	return int(unsafe.Sizeof(UriHeader{}))
}

func NewUriHeader(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofUriHeader()))
}

func (this *UriHeader) Encode(context *Context, buf *AbnfByteBuffer, charsets *CharsetInfo) {
	if this.name != ABNF_PTR_NIL {
		if !context.EncodeUriNoEscape {
			this.name.WriteCStringEscape(context, buf, charsets.nameCharsetIndex, charsets.nameMask)
		} else {
			this.name.WriteCString(context, buf)
		}

		if this.value != ABNF_PTR_NIL {
			buf.WriteByte('=')
			if !context.EncodeUriNoEscape {
				this.value.WriteCStringEscape(context, buf, charsets.valueCharsetIndex, charsets.valueMask)
			} else {
				this.value.WriteCString(context, buf)
			}
		}
	}
}

func (this *UriHeader) Parse(context *Context, charsets *CharsetInfo) (ok bool) {
	var name AbnfPtr
	var value AbnfPtr

	src := context.parseSrc
	len1 := AbnfPos(len(src))
	name, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsets.nameCharsetIndex, charsets.nameMask)
	if !ok {
		context.AddError(context.parsePos, "parse sip hname failed")
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

	value, ok = context.allocator.ParseAndAllocCStringEscapableEnableEmpty(context, charsets.valueCharsetIndex, charsets.valueMask)
	if !ok {
		context.AddError(context.parsePos, "parse uti hvalue failed")
		return false
	}
	this.value = value

	return true
}

func ParseUriHeaders(context *Context, charsets *CharsetInfo) (headers AbnfPtr, ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for uri headers")
		return ABNF_PTR_NIL, false
	}

	var prev *UriHeader = nil

	for context.parsePos < len1 {
		addr := NewUriHeader(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for uri headers")
			return ABNF_PTR_NIL, false
		}
		header := addr.GetUriHeader(context)
		ok = header.Parse(context, charsets)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if prev != nil {
			prev.next = addr
		} else {
			headers = addr
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

	return headers, true
}

func EncodeUriHeaders(context *Context, buf *AbnfByteBuffer, headers AbnfPtr, charsets *CharsetInfo) {
	header := headers.GetUriHeader(context)

	for {
		header.Encode(context, buf, charsets)
		if header.next == ABNF_PTR_NIL {
			return
		}
		buf.WriteByte('&')
		header = header.next.GetUriHeader(context)
	}
}

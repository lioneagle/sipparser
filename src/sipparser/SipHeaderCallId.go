package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderCallID struct {
	id1 AbnfPtr
	id2 AbnfPtr
}

func SizeofSipHeaderCallID() int {
	return int(unsafe.Sizeof(SipHeaderCallID{}))
}

func NewSipHeaderCallID(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderCallID()))
}

func (this *SipHeaderCallID) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderCallID) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderCallID())
}

func (this *SipHeaderCallID) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderCallID) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Call-ID: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderCallID) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.id1.WriteCString(context, buf)
	if this.id2 != ABNF_PTR_NIL {
		buf.WriteByte('@')
		this.id2.WriteCString(context, buf)
	}
}

/* RFC3261
 *
 * Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
 * callid   =  word [ "@" word ]
 */
func (this *SipHeaderCallID) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderCallID) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Call-ID header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Call-ID header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderCallID) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderCallID) ParseValueWithoutInit(context *Context) (ok bool) {
	this.id1, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_WORD, ABNF_CHARSET_MASK_SIP_WORD)
	if this.id1 == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "parse id1 failed for Call-ID header")
		return false
	}

	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		return true
	}

	if context.parseSrc[context.parsePos] == '@' {
		context.parsePos++
		this.id2, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_WORD, ABNF_CHARSET_MASK_SIP_WORD)
		if this.id2 == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "parse id2 failed for Call-ID header")
			return false
		}
	}

	return true
}

func (this *SipHeaderCallID) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'c' {
		pos++

		if (pos + 6) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'a') &&
			((src[pos+1] | 0x20) == 'l') &&
			((src[pos+2] | 0x20) == 'l') &&
			(src[pos+3] == '-') &&
			((src[pos+4] | 0x20) == 'i') &&
			((src[pos+5] | 0x20) == 'd') {
			if src[pos+6] == ':' || IsWspChar(src[pos+6]) {
				context.parsePos = pos + 6
				return true
			}
		}
	} else if src[pos]|0x20 == 'i' {
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

func ParseSipCallID(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderCallID(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Call-ID header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderCallID(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipCallIDValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderCallID(context).EncodeValue(context, buf)
}

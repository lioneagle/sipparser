package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipVersion struct {
	major AbnfPtr
	minor AbnfPtr
}

func SizeofSipVersion() int {
	return int(unsafe.Sizeof(SipVersion{}))
}

func NewSipVersion(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipVersion()))
}

func (this *SipVersion) Init() {
	ZeroMem(this.memAddr(), SizeofSipVersion())
}

func (this *SipVersion) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipVersion) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipVersion) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("SIP/")
	this.major.WriteCString(context, buf)
	buf.WriteByte('.')
	this.minor.WriteCString(context, buf)
}

/* RFC3261
 *
 * SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
 */
func (this *SipVersion) Parse(context *ParseContext) (ok bool) {
	ok = this.ParseStart(context)
	if !ok {
		context.AddError(context.parsePos, "parse start of SIP-Version failed")
		return false
	}

	return this.ParseAfterStart(context)
}

func (this *SipVersion) ParseAfterStart(context *ParseContext) (ok bool) {
	this.major, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT)
	if !ok {
		context.AddError(context.parsePos, "parse marjor of SIP-Version failed")
		return false
	}

	if context.parseSrc[context.parsePos] != '.' {
		context.AddError(context.parsePos, "no '.' after major of SIP-Version")
		return false
	}

	context.parsePos++

	this.minor, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT)
	if !ok {
		context.AddError(context.parsePos, "parse minor of SIP-Version failed")
		return false
	}

	return true
}

func (this *SipVersion) ParseStart(context *ParseContext) (ok bool) {
	/* 7 characters at least, such as SIP/2.0 */
	if (context.parsePos + 6) >= AbnfPos(len(context.parseSrc)) {
		return false
	}

	if ((context.parseSrc[context.parsePos] | 0x20) != 's') ||
		((context.parseSrc[context.parsePos+1] | 0x20) != 'i') ||
		((context.parseSrc[context.parsePos+2] | 0x20) != 'p') ||
		(context.parseSrc[context.parsePos+3] != '/') {
		return false
	}

	context.parsePos += 4
	return true
}

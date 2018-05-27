package sipparser

import (
	//"fmt"
	"unsafe"
)

const (
	SIP_VERSION_2_0 byte = 1
)

type SipVersion struct {
	version AbnfPtr
}

func SizeofSipVersion() int {
	return int(unsafe.Sizeof(SipVersion{}))
}

func NewSipVersion(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipVersion()))
}

func (this *SipVersion) Init() {
	ZeroMem(this.memAddr(), SizeofSipVersion())
}

func (this *SipVersion) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipVersion) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipVersion) Encode(context *Context, buf *AbnfByteBuffer) {
	if !this.version.IsAbnfPtr() {
		buf.WriteString("SIP/2.0")
	} else {
		buf.WriteString("SIP/")
		this.version.WriteCString(context, buf)
	}
}

/* RFC3261
 *
 * SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
 */
func (this *SipVersion) Parse(context *Context) (ok bool) {
	ok = this.ParseStart(context)
	if !ok {
		context.AddError(context.parsePos, "parse start of SIP-Version failed")
		return false
	}

	return this.ParseAfterStart(context)
}

func (this *SipVersion) ParseAfterStart(context *Context) (ok bool) {
	if (context.parseSrc[context.parsePos] == '2') &&
		(context.parseSrc[context.parsePos+1] == '.') &&
		(context.parseSrc[context.parsePos+2] == '0') {

		if ((context.parsePos + 3) >= AbnfPos(len(context.parseSrc))) ||
			!IsDigit(context.parseSrc[context.parsePos+3]) {
			context.parsePos += 3
			this.version = AbnfPtrSetValue(AbnfPtr(SIP_VERSION_2_0))
			return true
		}
	}

	majorStart := context.parsePos
	newPos := context.parsePos

	ref := &AbnfRef{}
	newPos = ref.Parse(context.parseSrc, newPos, ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT)
	if newPos <= majorStart {
		context.AddError(context.parsePos, "no marjor for SIP-Version ")
		return false
	}

	if context.parseSrc[newPos] != '.' {
		context.parsePos = newPos
		context.AddError(context.parsePos, "no '.' after major for SIP-Version")
		return false
	}

	minorStart := newPos + 1
	this.version, ok = context.allocator.ParseAndAllocCStringFromPos(context, minorStart, ABNF_CHARSET_DIGIT, ABNF_CHARSET_MASK_DIGIT)
	if !ok {
		context.AddError(context.parsePos, "parse minor failed for SIP-Version ")
		return false
	}

	if context.parsePos <= minorStart {
		context.AddError(context.parsePos, "no minor for SIP-Version ")
		return false
	}

	return true
}

func (this *SipVersion) ParseStart(context *Context) (ok bool) {
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

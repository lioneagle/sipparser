package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipStartLine struct {
	isRequest    bool
	statusCode   uint16
	method       SipMethod
	version      SipVersion
	addr         SipAddr
	reasonPhrase AbnfPtr
}

func SizeofSipStartLine() int {
	return int(unsafe.Sizeof(SipStartLine{}))
}

func NewSipStartLine(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipStartLine()))
}

func (this *SipStartLine) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipStartLine) Init() {
	ZeroMem(this.memAddr(), SizeofSipStartLine())
}

func (this *SipStartLine) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipStartLine) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	if this.isRequest {
		this.EncodeRequestLine(context, buf)
	} else {
		this.EncodeStatusLine(context, buf)
	}
	buf.WriteString("\r\n")
	//buf.WriteByte('\r')
	//buf.WriteByte('\n')
}

func (this *SipStartLine) EncodeRequestLine(context *ParseContext, buf *AbnfByteBuffer) {
	this.method.Encode(context, buf)
	buf.WriteByte(' ')
	this.addr.EncodeAddrSpec(context, buf)
	buf.WriteByte(' ')
	this.version.Encode(context, buf)
}

func (this *SipStartLine) EncodeStatusLine(context *ParseContext, buf *AbnfByteBuffer) {
	this.version.Encode(context, buf)
	buf.WriteByte(' ')
	EncodeUInt(buf, uint64(this.statusCode))
	buf.WriteByte(' ')
	this.reasonPhrase.WriteCStringEscape(context, buf, ABNF_CHARSET_SIP_REASON_PHRASE, ABNF_CHARSET_MASK_SIP_REASON_PHRASE)
}

/* RFC3261 Section 25.1, page 222
 *
 * Request-Line   =  Method SP Request-URI SP SIP-Version CRLF
 * Status-Line    =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
 * SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
 * Reason-Phrase  =  *(reserved / unreserved / escaped
 *                   / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
 * Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
 */
func (this *SipStartLine) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipStartLine) ParseWithoutInit(context *ParseContext) (ok bool) {
	if !this.version.ParseStart(context) {
		return this.ParseRequestLine(context)
	}

	return this.ParseStatusLineAfterVersionStart(context)
}

/* RFC3261 Section 25.1, page 222
 *
 * Request-Line   =  Method SP Request-URI SP SIP-Version CRLF
 * SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
 * Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
 */
func (this *SipStartLine) ParseRequestLine(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	if !this.method.Parse(context) {
		context.AddError(context.parsePos, "wrong Method for Request-Line")
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after Method for Request-Line")
		return false
	}

	if context.parseSrc[context.parsePos] != ' ' {
		context.AddError(context.parsePos, "no SP after Method for Request-Line")
		return false
	}

	context.parsePos++

	if !this.addr.parsAddrSpecWithoutInit(context, true) {
		context.AddError(context.parsePos, "wrong Method for Request-Line")
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after Request-URI for Request-Line")
		return false
	}

	if context.parseSrc[context.parsePos] != ' ' {
		context.AddError(context.parsePos, "no SP after Request-URI for Request-Line")
		return false
	}

	context.parsePos++

	if !this.version.Parse(context) {
		context.AddError(context.parsePos, "wrong SIP-Version for Request-Line")
		return false
	}

	if !ParseCRLF(context) {
		context.AddError(context.parsePos, "no CRLF for Request-Line")
		return false
	}

	this.isRequest = true

	return true
}

/* RFC3261 Section 25.1, page 222
 *
 * Status-Line    =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
 * SIP-Version    =  "SIP" "/" 1*DIGIT "." 1*DIGIT
 * Reason-Phrase  =  *(reserved / unreserved / escaped
 *                   / UTF8-NONASCII / UTF8-CONT / SP / HTAB)
 * Status-Code     =  Informational
 *               /   Redirection
 *               /   Success
 *               /   Client-Error
 *               /   Server-Error
 *               /   Global-Failure
 *               /   extension-code
 * extension-code  =  3DIGIT
 */
func (this *SipStartLine) ParseStatusLineAfterVersionStart(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	if !this.version.ParseAfterStart(context) {
		context.AddError(context.parsePos, "wrong SIP-Version for Status-Line")
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after SIP-Version for Status-Line")
		return false
	}

	if context.parseSrc[context.parsePos] != ' ' {
		context.AddError(context.parsePos, "no SP after SIP-Version for Status-Line")
		return false
	}

	context.parsePos++

	this.statusCode, _, context.parsePos, ok = ParseUInt16(context.parseSrc, context.parsePos)
	if !ok {
		context.AddError(context.parsePos, "wrong Status-Code for Status-Line")
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after SIP-Version for Status-Line")
		return false
	}

	if context.parseSrc[context.parsePos] != ' ' {
		context.AddError(context.parsePos, "no SP after SIP-Version for Status-Line")
		return false
	}

	context.parsePos++

	this.reasonPhrase, ok = context.allocator.ParseAndAllocCStringEscapableEnableEmpty(context, ABNF_CHARSET_SIP_REASON_PHRASE, ABNF_CHARSET_MASK_SIP_REASON_PHRASE)
	if !ok {
		context.AddError(context.parsePos, "wrong Reason-Phrase for Status-Line")
		return false
	}

	if !ParseCRLF(context) {
		context.AddError(context.parsePos, "no CRLF for Status-Line")
		return false
	}

	this.isRequest = false
	return true

}

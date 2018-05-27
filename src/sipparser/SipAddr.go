package sipparser

import (
	//"fmt"
	"unsafe"
)

const (
	ABNF_URI_UNKNOWN  = byte(0)
	ABNF_URI_ABSOLUTE = byte(1)
	ABNF_URI_SIP      = byte(2)
	ABNF_URI_SIPS     = byte(3)
	ABNF_URI_TEL      = byte(4)
	ABNF_URI_URN      = byte(5)
)

const (
	ABNF_SIP_ADDR_SPEC = byte(0)
	ABNF_SIP_NAME_ADDR = byte(1)
)

type SipAddr struct {
	addrType                  byte
	uriType                   byte
	displayNameIsQuotedString bool
	scheme                    AbnfPtr
	displayName               AbnfPtr
	addr                      AbnfPtr
}

func SizeofSipAddr() int {
	return int(unsafe.Sizeof(SipAddr{}))
}

func NewSipAddr(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipAddr()))
}

func (this *SipAddr) Init() {
	ZeroMem(this.memAddr(), SizeofSipAddr())
}

func (this *SipAddr) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipAddr) hasDisplayName() bool { return this.displayName == ABNF_PTR_NIL }
func (this *SipAddr) IsSipUri() bool       { return this.uriType == ABNF_URI_SIP }
func (this *SipAddr) IsSipsUri() bool      { return this.uriType == ABNF_URI_SIPS }

func (this *SipAddr) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipAddr) Encode(context *Context, buf *AbnfByteBuffer) {
	if this.addrType == ABNF_SIP_NAME_ADDR || context.EncodeUriAsNameSpace {
		if this.displayName != ABNF_PTR_NIL {
			if this.displayNameIsQuotedString {
				buf.WriteByte('"')
				this.displayName.WriteCString(context, buf)
				buf.WriteByte('"')
			} else {
				this.displayName.WriteCString(context, buf)
			}
		}
		buf.WriteByte('<')
	}

	if this.addr != ABNF_PTR_NIL {
		switch this.uriType {
		case ABNF_URI_SIP:
			fallthrough
		case ABNF_URI_SIPS:
			this.addr.GetSipUri(context).Encode(context, buf)
		case ABNF_URI_TEL:
			this.addr.GetTelUri(context).Encode(context, buf)
		}
	}

	if this.addrType == ABNF_SIP_NAME_ADDR || context.EncodeUriAsNameSpace {
		buf.WriteByte('>')
	}
}

func (this *SipAddr) EncodeAddrSpec(context *Context, buf *AbnfByteBuffer) {
	if this.addr != ABNF_PTR_NIL {
		switch this.uriType {
		case ABNF_URI_SIP:
			fallthrough
		case ABNF_URI_SIPS:
			this.addr.GetSipUri(context).Encode(context, buf)
		}
	}
}

/* RFC3261 Section 25.1, page 222
 *
 * name-addr =  [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
 * RAQUOT  =  ">" SWS ; right angle quote
 * LAQUOT  =  SWS "<"; left angle quote
 */
func (this *SipAddr) Parse(context *Context, parseAddrSpecParam bool) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context, parseAddrSpecParam)
}

/* RFC3261 Section 25.1, page 222
 *
 * name-addr =  [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
 * RAQUOT  =  ">" SWS ; right angle quote
 * LAQUOT  =  SWS "<"; left angle quote
 */
func (this *SipAddr) ParseWithoutInit(context *Context, parseAddrSpecParam bool) (ok bool) {
	begin := context.parsePos
	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		context.AddError(context.parsePos, "no value for sip addr")
		return false
	}

	if context.parseSrc[context.parsePos] == '<' || context.parseSrc[context.parsePos] == '"' {
		return this.ParseNameAddrWithoutInit(context)
	}

	ok = this.ParseScheme(context)
	if !ok {
		context.parsePos = begin
		return this.ParseNameAddrWithoutInit(context)
	}

	return this.parsAddrSpecAfterScheme(context, parseAddrSpecParam)

}

func (this *SipAddr) ParseNameAddrWithoutInit(context *Context) (ok bool) {
	context.parsePos, ok = ParseSWS(context.parseSrc, context.parsePos)
	if !ok {
		return false
	}

	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		context.AddError(context.parsePos, "no value for sip addr")
		return false
	}

	if context.parseSrc[context.parsePos] != '<' {
		ok = this.parseDisplayName(context)
		if !ok {
			return false
		}

		ok = ParseLeftAngleQuote(context)
		if !ok {
			return false
		}
	} else {
		context.parsePos++
	}

	ok = this.ParseScheme(context)
	if !ok {
		return false
	}

	ok = this.parsAddrSpecAfterScheme(context, true)
	if !ok {
		return false
	}

	ok = ParseRightAngleQuote(context)
	if !ok {
		return false
	}

	this.addrType = ABNF_SIP_NAME_ADDR

	return true
}

func (this *SipAddr) parsAddrSpecWithoutInit(context *Context, parseAddrSpecParam bool) (ok bool) {
	ok = this.ParseScheme(context)
	if !ok {
		return false
	}

	ok = this.parsAddrSpecAfterScheme(context, true)
	if !ok {
		return false
	}

	this.addrType = ABNF_SIP_ADDR_SPEC

	return true
}

func (this *SipAddr) parsAddrSpecAfterScheme(context *Context, parseAddrSpecParam bool) (ok bool) {
	switch this.uriType {
	case ABNF_URI_SIP:
		this.addr = NewSipUri(context)
		if this.addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for new sip uri")
			return false
		}
		uri := this.addr.GetSipUri(context)
		uri.SetSipUri()
		if parseAddrSpecParam {
			return uri.ParseAfterSchemeWithoutInit(context)
		}
		return uri.ParseAfterSchemeWithoutParam(context)

	case ABNF_URI_SIPS:
		this.addr = NewSipUri(context)
		if this.addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for new sips uri")
			return false
		}
		uri := this.addr.GetSipUri(context)
		uri.SetSipsUri()
		if parseAddrSpecParam {
			return uri.ParseAfterSchemeWithoutInit(context)
		}
		return uri.ParseAfterSchemeWithoutParam(context)

	case ABNF_URI_TEL:
		this.addr = NewTelUri(context)
		if this.addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for new tel uri")
			return false
		}
		uri := this.addr.GetTelUri(context)
		if parseAddrSpecParam {
			return uri.ParseAfterSchemeWithoutInit(context)
		}
		return uri.ParseAfterSchemeWithoutParam(context)
	}

	return false
}

/* RFC3261 Section 25.1, page 222
 *
 * display-name   =  *(token LWS)/ quoted-string
 */
func (this *SipAddr) parseDisplayName(context *Context) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		return true
	}

	if IsSipToken(context.parseSrc[context.parsePos]) {
		return this.parseTokens(context)
	}

	this.displayName, ok = context.allocator.ParseAndAllocSipQuotedString(context)
	if !ok {
		return false
	}

	this.displayNameIsQuotedString = true
	return true

}

func (this *SipAddr) parseTokens(context *Context) (ok bool) {
	//TODO: parse and alloc mem in future
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	newPos := context.parsePos
	this.displayNameIsQuotedString = false

	nameBegin := newPos
	for newPos < len1 {
		if !IsSipToken(src[newPos]) {
			break
		}

		ref := AbnfRef{}
		context.parsePos = ref.Parse(src, newPos, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		ok = ParseLWS(context)
		if !ok {
			context.parsePos = newPos
			context.AddError(newPos, "wrong LWS for display-name")
			return false
		}
		newPos = context.parsePos
	}

	context.parsePos = newPos

	this.displayName = AllocCString(context, src[nameBegin:newPos])
	if this.displayName == ABNF_PTR_NIL {
		context.AddError(newPos, "no mem for display-name")
		return false
	}
	return true
}

func (this *SipAddr) ParseScheme(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos
	begin := context.parsePos

	if pos >= len1 {
		return false
	}

	switch src[pos] | 0x20 {
	case 's':
		pos++
		if (pos + 2) >= len1 {
			break
		}
		if ((src[pos] | 0x20) == 'i') &&
			((src[pos+1] | 0x20) == 'p') {
			if src[pos+2] == ':' {
				context.parsePos = pos + 3
				this.uriType = ABNF_URI_SIP
				return true
			}
			if (src[pos+2] | 0x20) == 's' {
				if (pos + 3) >= len1 {
					context.parsePos = pos + 3
					return false
				}
				if src[pos+3] == ':' {
					context.parsePos = pos + 4
					this.uriType = ABNF_URI_SIPS
					return true
				}
			}
		}
	case 't':
		pos++
		if (pos + 2) >= len1 {
			break
		}
		if ((src[pos] | 0x20) == 'e') &&
			((src[pos+1] | 0x20) == 'l') {
			if src[pos+2] == ':' {
				context.parsePos = pos + 3
				this.uriType = ABNF_URI_TEL
				return true
			}
		}
	case 'u':
		pos++
		if (pos + 2) >= len1 {
			break
		}
		if ((src[pos] | 0x20) == 'r') &&
			((src[pos+1] | 0x20) == 'n') {
			if src[pos+2] == ':' {
				context.parsePos = pos + 3
				this.uriType = ABNF_URI_URN
				return true
			}
		}
	}

	if IsAlpha(src[begin]) {
		var ok bool

		context.parsePos = begin
		this.scheme, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_URI_SCHEME, ABNF_CHARSET_MASK_URI_SCHEME)
		if !ok {
			return false
		}

		if context.parsePos >= len1 {
			return false
		}

		if src[context.parsePos] != ':' {
			return false
		}
		context.parsePos++
		this.uriType = ABNF_URI_ABSOLUTE
		return true
	}

	return false
}

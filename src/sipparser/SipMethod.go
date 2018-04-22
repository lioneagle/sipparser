package sipparser

import (
	"unsafe"
)

const (
	ABNF_SIP_METHOD_UNKNOWN   byte = 0
	ABNF_SIP_METHOD_INVITE    byte = 1
	ABNF_SIP_METHOD_PRACK     byte = 2
	ABNF_SIP_METHOD_UPDATE    byte = 3
	ABNF_SIP_METHOD_INFO      byte = 4
	ABNF_SIP_METHOD_ACK       byte = 5
	ABNF_SIP_METHOD_BYE       byte = 6
	ABNF_SIP_METHOD_REGISTER  byte = 7
	ABNF_SIP_METHOD_SUBSCRIBE byte = 8
	ABNF_SIP_METHOD_NOTIFY    byte = 9
	ABNF_SIP_METHOD_REFER     byte = 10
	ABNF_SIP_METHOD_OPTIONS   byte = 11
	ABNF_SIP_METHOD_MESSAGE   byte = 12
	ABNF_SIP_METHOD_PUBLISH   byte = 13
)

var g_sipMethodName = []string{
	ABNF_SIP_METHOD_UNKNOWN:   "UKNOWN",
	ABNF_SIP_METHOD_INVITE:    "INVITE",
	ABNF_SIP_METHOD_PRACK:     "PRACK",
	ABNF_SIP_METHOD_UPDATE:    "UPDATE",
	ABNF_SIP_METHOD_INFO:      "INFO",
	ABNF_SIP_METHOD_ACK:       "ACK",
	ABNF_SIP_METHOD_BYE:       "BYE",
	ABNF_SIP_METHOD_REGISTER:  "REGISTER",
	ABNF_SIP_METHOD_SUBSCRIBE: "SUBSCRIBE",
	ABNF_SIP_METHOD_NOTIFY:    "NOTIFY",
	ABNF_SIP_METHOD_REFER:     "REFER",
	ABNF_SIP_METHOD_OPTIONS:   "OPTIONS",
	ABNF_SIP_METHOD_MESSAGE:   "MESSAGE",
	ABNF_SIP_METHOD_PUBLISH:   "PUBLISH",
}

type SipMethod struct {
	method        byte
	unknownMethod AbnfPtr
}

func SizeofSipMethod() int {
	return int(unsafe.Sizeof(SipMethod{}))
}

func NewSipMethod(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMethod()))
}

func (this *SipMethod) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMethod) Init() {
	ZeroMem(this.memAddr(), SizeofSipMethod())
}

func (this *SipMethod) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipMethod) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	if this.method != ABNF_SIP_METHOD_UNKNOWN {
		buf.WriteString(g_sipMethodName[this.method])
	} else {
		this.unknownMethod.WriteCString(context, buf)
	}
}

/*
 * Method            =  INVITEm / ACKm / OPTIONSm / BYEm
 *                     / CANCELm / REGISTERm
 *                     / extension-method
 * extension-method  =  token
 */
func (this *SipMethod) Parse(context *ParseContext) (ok bool) {
	var newPos AbnfPos
	this.method, newPos = GetSipMethodIndex(context.parseSrc, context.parsePos)

	if this.method == ABNF_SIP_METHOD_UNKNOWN {
		this.unknownMethod, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		return ok
	} else {
		context.parsePos = newPos
	}
	return true
}

func GetSipMethodIndex(src []byte, pos AbnfPos) (byte, AbnfPos) {
	len1 := AbnfPos(len(src))

	if pos >= len1 {
		return ABNF_SIP_METHOD_UNKNOWN, pos
	}

	switch src[pos] {
	case 'A':
		pos++
		if (pos + 1) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'C') &&
			(src[pos+1] == 'K') {
			pos += 2
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_ACK, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'B':
		pos++
		if (pos + 1) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'Y') &&
			(src[pos+1] == 'E') {
			pos += 2
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_BYE, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'I':
		pos++
		if (pos < len1) && (src[pos] == 'N') {
			pos++
			switch src[pos] {
			case 'F':
				pos++
				if (pos < len1) && (src[pos] == 'O') {
					pos++
					if (pos >= len1) || !IsSipToken(src[pos]) {
						return ABNF_SIP_METHOD_INFO, pos
					}
				}
				return ABNF_SIP_METHOD_UNKNOWN, pos
			case 'V':
				pos++
				if (pos + 2) >= len1 {
					return ABNF_SIP_METHOD_UNKNOWN, pos
				}
				if (src[pos] == 'I') &&
					(src[pos+1] == 'T') &&
					(src[pos+2] == 'E') {
					pos += 3
					if (pos >= len1) || !IsSipToken(src[pos]) {
						return ABNF_SIP_METHOD_INVITE, pos
					}
				}
				return ABNF_SIP_METHOD_UNKNOWN, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'M':
		pos++
		if (pos + 5) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'E') &&
			(src[pos+1] == 'S') &&
			(src[pos+2] == 'S') &&
			(src[pos+3] == 'A') &&
			(src[pos+4] == 'G') &&
			(src[pos+5] == 'E') {
			pos += 6
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_MESSAGE, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'N':
		pos++
		if (pos + 4) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'O') &&
			(src[pos+1] == 'T') &&
			(src[pos+2] == 'I') &&
			(src[pos+3] == 'F') &&
			(src[pos+4] == 'Y') {
			pos += 5
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_NOTIFY, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'O':
		pos++
		if (pos + 5) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'P') &&
			(src[pos+1] == 'T') &&
			(src[pos+2] == 'I') &&
			(src[pos+3] == 'O') &&
			(src[pos+4] == 'N') &&
			(src[pos+5] == 'S') {
			pos += 6
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_OPTIONS, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'P':
		pos++
		switch src[pos] {
		case 'R':
			pos++
			if (pos + 2) >= len1 {
				return ABNF_SIP_METHOD_UNKNOWN, pos
			}
			if (src[pos] == 'A') &&
				(src[pos+1] == 'C') &&
				(src[pos+2] == 'K') {
				pos += 3
				if (pos >= len1) || !IsSipToken(src[pos]) {
					return ABNF_SIP_METHOD_PRACK, pos
				}
			}
			return ABNF_SIP_METHOD_UNKNOWN, pos
		case 'U':
			pos++
			if (pos + 4) >= len1 {
				return ABNF_SIP_METHOD_UNKNOWN, pos
			}
			if (src[pos] == 'B') &&
				(src[pos+1] == 'L') &&
				(src[pos+2] == 'I') &&
				(src[pos+3] == 'S') &&
				(src[pos+4] == 'H') {
				pos += 5
				if (pos >= len1) || !IsSipToken(src[pos]) {
					return ABNF_SIP_METHOD_PUBLISH, pos
				}
			}
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'R':
		pos++
		if (pos < len1) && (src[pos] == 'E') {
			pos++
			switch src[pos] {
			case 'F':
				pos++
				if (pos + 1) >= len1 {
					return ABNF_SIP_METHOD_UNKNOWN, pos
				}
				if (src[pos] == 'E') &&
					(src[pos+1] == 'R') {
					pos += 2
					if (pos >= len1) || !IsSipToken(src[pos]) {
						return ABNF_SIP_METHOD_REFER, pos
					}
				}
				return ABNF_SIP_METHOD_UNKNOWN, pos
			case 'G':
				pos++
				if (pos + 4) >= len1 {
					return ABNF_SIP_METHOD_UNKNOWN, pos
				}
				if (src[pos] == 'I') &&
					(src[pos+1] == 'S') &&
					(src[pos+2] == 'T') &&
					(src[pos+3] == 'E') &&
					(src[pos+4] == 'R') {
					pos += 5
					if (pos >= len1) || !IsSipToken(src[pos]) {
						return ABNF_SIP_METHOD_REGISTER, pos
					}
				}
				return ABNF_SIP_METHOD_UNKNOWN, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'S':
		pos++
		if (pos + 7) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'U') &&
			(src[pos+1] == 'B') &&
			(src[pos+2] == 'S') &&
			(src[pos+3] == 'C') &&
			(src[pos+4] == 'R') &&
			(src[pos+5] == 'I') &&
			(src[pos+6] == 'B') &&
			(src[pos+7] == 'E') {
			pos += 8
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_SUBSCRIBE, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	case 'U':
		pos++
		if (pos + 4) >= len1 {
			return ABNF_SIP_METHOD_UNKNOWN, pos
		}
		if (src[pos] == 'P') &&
			(src[pos+1] == 'D') &&
			(src[pos+2] == 'A') &&
			(src[pos+3] == 'T') &&
			(src[pos+4] == 'E') {
			pos += 5
			if (pos >= len1) || !IsSipToken(src[pos]) {
				return ABNF_SIP_METHOD_UPDATE, pos
			}
		}
		return ABNF_SIP_METHOD_UNKNOWN, pos
	}

	return ABNF_SIP_METHOD_UNKNOWN, pos
}

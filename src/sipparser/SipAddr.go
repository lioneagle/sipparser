package sipparser

import (
	"unsafe"
)

const (
	ABNF_URI_UNKNOWN   = byte(0)
	ABNF_URI_SIP       = byte(1)
	ABNF_URI_SIPS      = byte(2)
	ABNF_URI_TEL       = byte(3)
	ABNF_URI_ABSOULUTE = byte(4)
)

const (
	ABNF_SIP_ADDR_SPEC = byte(0)
	ABNF_SIP_NAME_ADDR = byte(1)
)

type SipAddr struct {
	addrType                  byte
	uriType                   byte
	displayNameIsQuotedString bool
	displayName               AbnfPtr
	uri                       AbnfPtr
}

func SizeofSipAddr() int {
	return int(unsafe.Sizeof(SipAddr{}))
}

func NewSipAddr(context *ParseContext) AbnfPtr {
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

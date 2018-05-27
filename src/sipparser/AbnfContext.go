package sipparser

import (
	_ "fmt"
	//"log"
	"unsafe"
)

type Context struct {
	Errors                                  AbnfErrors
	EncodeHeaderShorName                    bool
	allocator                               *MemAllocator
	parseSrc                                []byte
	parsePos                                AbnfPos
	srcLen                                  AbnfPos
	parseBegin                              uintptr
	parseEnd                                uintptr
	parseCur                                uintptr
	ParseSipHeaderAsRaw                     bool
	ParseSetSipUriKnownParam                bool
	ParseSetSipFromKnownParam               bool
	ParseSetSipToKnownParam                 bool
	ParseSetSipRouteKnownParam              bool
	ParseSetSipRecordRouteKnownParam        bool
	ParseSetSipContactKnownParam            bool
	ParseSetSipViaKnownParam                bool
	ParseSetSipContentTypeKnownParam        bool
	ParseSetSipContentDispositionKnownParam bool
	ParseSetTelUriKnownParam                bool
	ParseSetSipPathKnownParam               bool
	ParseSetSipServiceRouteKnownParam       bool
	//ParseSipKeyHeader    bool

	EncodeUriAsNameSpace       bool
	EncodeUriNoEscape          bool
	EncodeReasonPhraseNoEscape bool

	SipHeaders SipHeaderInfos
}

func NewContext() *Context {
	ret := &Context{}
	ret.ParseSetSipContentTypeKnownParam = true
	ret.EncodeUriAsNameSpace = true
	ret.SipHeaders = g_SipHeaderInfos
	return ret
}

func (this *Context) SetParseSrc(src []byte) {
	this.Errors.src = src
	this.parseSrc = src
	this.srcLen = AbnfPos(len(src))
	if len(src) > 0 {
		this.parseBegin = uintptr(unsafe.Pointer(&src[0]))
		this.parseEnd = this.parseBegin + uintptr(len(src))
	} else {
		this.parseBegin = 0
		this.parseEnd = 0
	}
}

func (this *Context) SetParsePos(pos AbnfPos) {
	this.parsePos = pos
}

func (this *Context) GetParsePos() AbnfPos {
	return this.parsePos
}

func (this *Context) AddError(pos AbnfPos, description string) {
	fileName, pc, line := GetCallerInfoN(2)
	this.Errors.Add(&AbnfError{src: this.parseSrc, pos: pos, description: description, fileName: fileName, pc: pc, line: line})
}

func (this *Context) SetAllocator(allocator *MemAllocator) {
	this.allocator = allocator
}

func (this *Context) ClearAllocNum() {
	this.allocator.ClearAllocNum()
}

func (this *Context) GetAllocNum() uint32 {
	return this.allocator.AllocNum()
}

func (this *Context) FreePart(remain uint32) {
	this.allocator.FreePart(remain)
}

func (this *Context) Used() uint32 {
	return this.allocator.Used()
}

package sipparser

import (
	_ "fmt"
	//"log"
	"unsafe"
)

type ParseContext struct {
	Errors                                  AbnfErrors
	EncodeHeaderShorName                    bool
	allocator                               *MemAllocator
	parseSrc                                []byte
	parsePos                                AbnfPos
	parseBegin                              uintptr
	parseEnd                                uintptr
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
	//ParseSipKeyHeader    bool
}

func NewParseContext() *ParseContext {
	return &ParseContext{}
}

func (this *ParseContext) SetParseSrc(src []byte) {
	this.Errors.src = src
	this.parseSrc = src
	if len(src) > 0 {
		this.parseBegin = uintptr(unsafe.Pointer(&src[0]))
		this.parseEnd = this.parseBegin + uintptr(len(src))
	} else {
		this.parseBegin = 0
		this.parseEnd = 0
	}
}

func (this *ParseContext) SetParsePos(pos AbnfPos) {
	this.parsePos = pos
}

func (this *ParseContext) GetParsePos() AbnfPos {
	return this.parsePos
}

func (this *ParseContext) AddError(pos AbnfPos, description string) {
	fileName, pc, line := GetCallerInfoN(2)
	this.Errors.Add(&AbnfError{pos: pos, description: description, fileName: fileName, pc: pc, line: line})
}

func (this *ParseContext) SetAllocator(allocator *MemAllocator) {
	this.allocator = allocator
}

func (this *ParseContext) ClearAllocNum() {
	this.allocator.ClearAllocNum()
}

func (this *ParseContext) GetAllocNum() uint32 {
	return this.allocator.AllocNum()
}

func (this *ParseContext) FreePart(remain uint32) {
	this.allocator.FreePart(remain)
}

func (this *ParseContext) Used() uint32 {
	return this.allocator.Used()
}

package sipparser

import (
	"fmt"
	//"runtime"
)

type AbnfError struct {
	description string
	src         []byte
	pos         AbnfPos
	fileName    string
	pc          uintptr
	line        int
}

func (this *AbnfError) Error() string {
	return this.String()
}

func (this *AbnfError) String() string {
	buf := NewAbnfByteBuffer(nil)
	this.Write(buf)
	return buf.String()
}

func (this *AbnfError) Write(buf *AbnfByteBuffer) {
	//funcName := runtime.FuncForPC(this.pc).Name()
	if this.pos < AbnfPos(len(this.src)) {
		fmt.Println("here1")
		num := AbnfPos(20)
		if AbnfPos(len(this.src)) < (this.pos + num) {
			num = AbnfPos(len(this.src)) - this.pos
		}
		buf.Printf("%s:%d: %s at src[%d]: %s", this.fileName, this.line,
			this.description, this.pos, string(this.src[this.pos:this.pos+num]))
		return
	}
	description := this.description

	if len(description) == 0 {
		description = "unknown error"
	}
	buf.Printf("%s:%d: %s", this.fileName, this.line, this.description)
}

type AbnfErrors struct {
	src    []byte
	errors []*AbnfError
}

func (this *AbnfErrors) Len() int {
	return len(this.errors)
}

func (this *AbnfErrors) Add(err *AbnfError) {
	this.errors = append(this.errors, err)
}

func (this *AbnfErrors) String() string {
	buf := NewAbnfByteBuffer(nil)
	this.Write(buf)
	return buf.String()
}

func (this *AbnfErrors) Write(buf *AbnfByteBuffer) {
	len1 := len(this.errors)
	for i := len1 - 1; i >= 0; i-- {
		buf.Printf("[%d]: ", len1-i)
		this.errors[i].Write(buf)
		buf.Printfln("")
	}
}

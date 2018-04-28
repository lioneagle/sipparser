package sipparser

import (
	//"bytes"
	//"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/lioneagle/goutil/src/buffer"
)

//type AbnfByteBuffer = bytes.Buffer
type AbnfByteBuffer = buffer.ByteBuffer

func NewAbnfByteBuffer(buf []byte) *AbnfByteBuffer {
	return buffer.NewByteBuffer(buf)
}

var print_mem bool = false

type AbnfPos = uint

type AbnfIsInCharset func(ch byte) bool

type AbnfEncoder interface {
	Encode(context *ParseContext, buf *AbnfByteBuffer)
}

func AbnfEncoderToString(context *ParseContext, encoder AbnfEncoder) string {
	//var buf AbnfByteBuffer
	buf := NewAbnfByteBuffer(make([]byte, 64))
	encoder.Encode(context, buf)
	return buf.String()
}

func StringToByteSlice(str string) []byte {
	strHeader := (*reflect.StringHeader)(unsafe.Pointer(&str))
	retHeader := reflect.SliceHeader{Data: strHeader.Data, Len: strHeader.Len, Cap: strHeader.Len}
	return *(*[]byte)(unsafe.Pointer(&retHeader))
}

func StringToByteSlice2(str string) *[]byte {
	strHeader := (*reflect.StringHeader)(unsafe.Pointer(&str))
	retHeader := reflect.SliceHeader{Data: strHeader.Data, Len: strHeader.Len, Cap: strHeader.Len}
	return (*[]byte)(unsafe.Pointer(&retHeader))
}

func ByteSliceToString(bytes []byte) string {
	return *(*string)(unsafe.Pointer(&bytes))
}

func CallerName() string {
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return ""
	}
	return runtime.FuncForPC(pc).Name()
}

func CallerNameN(n int) string {
	pc, _, _, ok := runtime.Caller(n)
	if !ok {
		return ""
	}
	return runtime.FuncForPC(pc).Name()
}

func GetCallerInfoN(n int) (fileName string, pc uintptr, line int) {
	pc, fileName, line, ok := runtime.Caller(n)
	if ok {
		return filepath.Base(fileName), pc, line
	}
	return "unknown-file", 0, -1
}

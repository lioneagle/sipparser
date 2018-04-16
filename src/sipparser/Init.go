package sipparser

import (
	"fmt"
	"unsafe"
)

func init() {
	/*for i, v := range g_SipHeaderInfos {
		v.index = SipHeaderIndexType(i)
	}*/

	printSize()

}

func printSize() {
	fmt.Println("sizeof(bool)                 =", unsafe.Sizeof(true))
	fmt.Println("sizeof(int)                  =", unsafe.Sizeof(1))
	fmt.Println("sizeof(AbnfPtr)              =", unsafe.Sizeof(AbnfPtr(1)))
	fmt.Println("sizeof(AbnfRef)              =", unsafe.Sizeof(AbnfRef{}))
	fmt.Println("sizeof(SipHostPort)          =", unsafe.Sizeof(SipHostPort{}))
	fmt.Println("sizeof(SipUri)               =", unsafe.Sizeof(SipUri{}))
	fmt.Println("sizeof(SipUriKnownParams)    =", unsafe.Sizeof(SipUriKnownParams{}))
	fmt.Println("sizeof(SipAddr)              =", unsafe.Sizeof(SipAddr{}))
	fmt.Println("SIP_URI_KNOWN_PARAM_MAX_NUM  =", SIP_URI_KNOWN_PARAM_MAX_NUM)
}

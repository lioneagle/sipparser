package sipparser

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lioneagle/goutil/src/test"
)

func TestGetSipHeaderIndex(t *testing.T) {
	for i, v := range g_SipHeaderInfos {
		if v == nil {
			continue
		}

		v := v
		j := i
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			//t.Parallel()

			index, _ := GetSipHeaderIndex(v.name, 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", v.name)

			index, _ = GetSipHeaderIndex(bytes.ToLower(v.name), 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", bytes.ToLower(v.name))

			index, _ = GetSipHeaderIndex(bytes.ToUpper(v.name), 0)
			test.EXPECT_EQ(t, index, SipHeaderIndexType(j), "header name = %s", bytes.ToUpper(v.name))
		})
	}
}

func BenchmarkGetSipHeaderIndex(b *testing.B) {
	b.StopTimer()
	b.SetBytes(2)
	b.ReportAllocs()

	var testdata []*SipHeaderInfo

	for _, v := range g_SipHeaderInfos {
		if v != nil {
			testdata = append(testdata, v)
		}
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		//for _, v := range g_SipHeaderInfos {
		for _, v := range testdata {
			GetSipHeaderIndex(v.name, 0)
		}
	}
}

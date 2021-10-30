package main

import "C"


func StrCmp(str1 string, str2 *C.char) bool {

	strC := C.GoString(str2)

	return str1 == strC
}

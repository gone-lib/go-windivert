// Code generated by "stringer -type=Mode -output=enums_string.go -linecomment"; DO NOT EDIT.

package main

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[List-0]
	_ = x[Watch-1]
	_ = x[Kill-2]
	_ = x[Uninstall-3]
}

const _Mode_name = "ListWatchKillUninstall"

var _Mode_index = [...]uint8{0, 4, 9, 13, 22}

func (i Mode) String() string {
	if i >= Mode(len(_Mode_index)-1) {
		return "Mode(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Mode_name[_Mode_index[i]:_Mode_index[i+1]]
}
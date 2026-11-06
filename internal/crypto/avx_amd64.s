#include "textflag.h"

// func vzeroupper()
TEXT ·vzeroupper(SB), NOSPLIT, $0-0
	VZEROUPPER
	RET

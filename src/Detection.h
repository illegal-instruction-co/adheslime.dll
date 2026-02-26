#pragma once
#include "Common.h"

void RunNativeChecks();
void RunHeavyChecks();
void CaptureDetectionBaselines();

extern DetectionFunc g_nativeDispatch[];

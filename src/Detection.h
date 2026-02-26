#pragma once
#include "Common.h"

// Native detection functions
void RunNativeChecks();
void CaptureDetectionBaselines();

// Dispatch table access (for TriggerSelfTamper)
extern DetectionFunc g_nativeDispatch[];

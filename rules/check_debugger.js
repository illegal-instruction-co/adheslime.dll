// rules/check_debugger.js - Debugger detection rule
// Uses native bindings to detect attached debuggers and timing anomalies

if (native.isDebuggerPresent()) {
    native.reportBan(0xA00A, "debugger_attached");
}

if (native.checkTimingAnomaly()) {
    native.reportBan(0xA002, "timing_anomaly_js");
}

native.log("check_debugger.js executed");

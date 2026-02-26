// rules/check_integrity.js — Module integrity and anti-tamper checks
// Verifies .text section CRC, hardware breakpoints, and ntapi hooks

if (!native.verifyTextIntegrity()) {
    native.reportBan(0xA005, "text_tampered_js");
}

if (native.checkHardwareBreakpoints()) {
    native.reportBan(0xA003, "hwbp_detected_js");
}

if (native.scanNtapiHooks()) {
    native.reportBan(0xA006, "ntapi_hooked_js");
}

native.log("check_integrity.js executed");

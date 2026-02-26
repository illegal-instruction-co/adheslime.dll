// rules/check_processes.js — Blacklisted process/window detection
// Scans for known reverse engineering and cheat tools

var blacklist = [ // NOSONAR
    "x64dbg",
    "Cheat Engine",
    "Process Hacker",
    "IDA",
    "OllyDbg",
    "Wireshark"
];

for (var i = 0; i < blacklist.length; i++) { // NOSONAR
    if (native.findWindow(blacklist[i])) {
        native.reportBan(0xA007, "blacklisted:" + blacklist[i]);
    }
}

native.log("check_processes.js executed");

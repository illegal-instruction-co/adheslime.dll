// rules/check_processes.js - Blacklisted process/window detection
// Only targets actual game cheat tools, not general development/RE tools

var blacklist = [ // NOSONAR
    "Cheat Engine",
    "CheatEngine"
];

for (var i = 0; i < blacklist.length; i++) { // NOSONAR
    if (native.findWindow(blacklist[i])) {
        native.reportBan(0xA007, "blacklisted:" + blacklist[i]);
    }
}

native.log("check_processes.js executed");

#pragma once
#include "Common.h"

void LoadEmbeddedRules();
int  LoadRuleFromFile(string_view path);
int  LoadRulesFromDirectory(string_view dir);

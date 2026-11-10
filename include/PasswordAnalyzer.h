
#ifndef PASSWORDANALYZER_H
#define PASSWORDANALYZER_H

#include <string>
#include <vector>

using namespace std;

struct PasswordAnalysis {
    int score;
    string strength;
    vector<string> suggestions;
};

class PasswordAnalyzer {
public:
    static PasswordAnalysis analyze(const string& password);
};

#endif


#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <cctype>

using namespace std;

struct Packet {
    string sourceIP;
    string destinationIP;
    int sourcePort = 0;
    int destinationPort = 0;
    string protocol;
    int packetSize = 0;
    time_t timestamp = 0;
};

struct Alert {
    string type;
    string message;
    string sourceIP;
    string timestamp;
};

string trim(const string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

vector<string> splitCSV(const string& line) {
    vector<string> fields;
    string field;
    stringstream ss(line);

    while (getline(ss, field, ',')) {
        fields.push_back(trim(field));
    }

    if (!line.empty() && line.back() == ',')
        fields.push_back("");
    return fields;
}

bool parseTimestamp(const string& input, time_t& result) {
    string value = trim(input);

    if (value.empty()) return false;

    // Unix timestamp
    bool digitsOnly = all_of(
        value.begin(), value.end(),
        [](unsigned char c) { return isdigit(c); }
    );

    if (digitsOnly) {
        try {
            result = static_cast<time_t>(stoll(value));
            return true;
        } catch (...) {
            return false;
        }
    }

    // MM/DD/YYYY HH:MM
    // Example: 10/9/2026 10:00
    {
        tm timeInfo = {};
        istringstream ss(value);
        ss >> get_time(&timeInfo, "%m/%d/%Y %H:%M");

        if (!ss.fail()) {
            ss >> ws;
            if (ss.eof()) {
                timeInfo.tm_isdst = -1;
                result = mktime(&timeInfo);
                return result != static_cast<time_t>(-1);
            }
        }
    }

    // MM/DD/YYYY HH:MM:SS
    {
        tm timeInfo = {};
        istringstream ss(value);
        ss >> get_time(&timeInfo, "%m/%d/%Y %H:%M:%S");

        if (!ss.fail()) {
            ss >> ws;
            if (ss.eof()) {
                timeInfo.tm_isdst = -1;
                result = mktime(&timeInfo);
                return result != static_cast<time_t>(-1);
            }
        }
    }

    if (value.size() == 19 && value[10] == 'T')
        value[10] = ' ';

    // YYYY-MM-DD HH:MM:SS
    {
        tm timeInfo = {};
        istringstream ss(value);
        ss >> get_time(&timeInfo, "%Y-%m-%d %H:%M:%S");

        if (!ss.fail()) {
            ss >> ws;
            if (ss.eof()) {
                timeInfo.tm_isdst = -1;
                result = mktime(&timeInfo);
                return result != static_cast<time_t>(-1);
            }
        }
    }

    return false;
}

string formatTimestamp(time_t timestamp) {
    tm* timeInfo = localtime(&timestamp);

    if (timeInfo == nullptr)
        return "Unknown";

    ostringstream output;
    output << put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

bool loadCSV(const string& filename, vector<Packet>& packets) {
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "Error: Cannot open CSV file: " << filename << '\n';
        return false;
    }

    string line;

    if (!getline(file, line)) {
        cerr << "Error: CSV file is empty.\n";
        return false;
    }

    int lineNumber = 1;
    int skipped = 0;

    while (getline(file, line)) {
        ++lineNumber;

        if (trim(line).empty())
            continue;

        vector<string> fields = splitCSV(line);

        if (fields.size() != 7) {
            cerr << "Warning: Row " << lineNumber
                 << " does not contain seven columns.\n";
            ++skipped;
            continue;
        }

        try {
            Packet p;

            p.sourceIP = fields[0];
            p.destinationIP = fields[1];
            p.sourcePort = stoi(fields[2]);
            p.destinationPort = stoi(fields[3]);
            p.protocol = fields[4];
            p.packetSize = stoi(fields[5]);

            transform(
                p.protocol.begin(),
                p.protocol.end(),
                p.protocol.begin(),
                [](unsigned char c) {
                    return static_cast<char>(toupper(c));
                }
            );

            if (p.sourceIP.empty() ||
                p.destinationIP.empty() ||
                p.sourcePort < 0 || p.sourcePort > 65535 ||
                p.destinationPort < 0 || p.destinationPort > 65535 ||
                p.packetSize < 0 ||
                !parseTimestamp(fields[6], p.timestamp)) {

                cerr << "Warning: Invalid data on row "
                     << lineNumber << ".\n";
                ++skipped;
                continue;
            }

            packets.push_back(p);
        }
        catch (...) {
            cerr << "Warning: Could not parse row "
                 << lineNumber << ".\n";
            ++skipped;
        }
    }

    cout << "\nRecords loaded: " << packets.size() << '\n';

    if (skipped > 0)
        cout << "Invalid rows skipped: " << skipped << '\n';

    return !packets.empty();
}

void addAlert(
    vector<Alert>& alerts,
    const string& type,
    const string& message,
    const string& sourceIP,
    time_t timestamp
) {
    alerts.push_back({
        type,
        message,
        sourceIP,
        formatTimestamp(timestamp)
    });
}

vector<Alert> analyseTraffic(const vector<Packet>& packets) {
    vector<Alert> alerts;

    // Large packets greater than 1500 bytes.
    for (const Packet& p : packets) {
        if (p.packetSize > 1500) {
            addAlert(
                alerts,
                "LARGE_PACKET",
                "Packet size " + to_string(p.packetSize) +
                    " bytes exceeds 1500 bytes.",
                p.sourceIP,
                p.timestamp
            );
        }
    }

    // More than 100 records from the same source IP
    map<string, vector<time_t>> sourceTimes;

    for (const Packet& p : packets)
        sourceTimes[p.sourceIP].push_back(p.timestamp);

    for (auto& entry : sourceTimes) {
        vector<time_t>& times = entry.second;
        sort(times.begin(), times.end());

        size_t left = 0;

        for (size_t right = 0; right < times.size(); ++right) {
            while (times[right] - times[left] > 10)
                ++left;

            if (right - left + 1 > 100) {
                addAlert(
                    alerts,
                    "HIGH_TRAFFIC",
                    "More than 100 packet records from source IP " +
                        entry.first + " within 10 seconds.",
                    entry.first,
                    times[right]
                );
                // Report once per source IP.
                break;
            }
        }
    }

    //Protocol represents more than 80% of all records.
    map<string, size_t> protocolCounts;

    for (const Packet& p : packets)
        ++protocolCounts[p.protocol];

    for (const auto& entry : protocolCounts) {
        double percentage =
            100.0 * static_cast<double>(entry.second) /
            static_cast<double>(packets.size());

        if (percentage > 80.0) {
            ostringstream message;

            message << entry.first << " represents "
                    << fixed << setprecision(2) << percentage
                    << "% of records (threshold: 80%).";

            addAlert(
                alerts,
                "PROTOCOL_DISTRIBUTION",
                message.str(),
                "-",
                packets.front().timestamp
            );
        }
    }

    return alerts;
}

bool saveReport(
    const string& filename,
    const vector<Packet>& packets,
    const vector<Alert>& alerts
) {
    ofstream report(filename);

    if (!report.is_open()) {
        cerr << "Error: Cannot create report file: "
             << filename << '\n';
        return false;
    }

    report << "NETWORK TRAFFIC ANOMALY ANALYSER\n";
    report << "OFFLINE ANALYSIS REPORT\n";
    report << "========================================\n";
    report << "Records analysed: " << packets.size() << '\n';
    report << "Alerts generated: " << alerts.size() << "\n\n";

    if (alerts.empty()) {
        report << "No configured anomaly rules were triggered.\n";
    } else {
        report << "ALERT DETAILS\n";
        report << "------------\n";

        for (size_t i = 0; i < alerts.size(); ++i) {
            report << i + 1 << ". [" << alerts[i].type << "]\n";
            report << "   " << alerts[i].message << '\n';
            report << "   Source IP: " << alerts[i].sourceIP << '\n';
            report << "   Timestamp: " << alerts[i].timestamp
                   << "\n\n";
        }
    }

    report << "Note: Alerts are rule-based indicators, "
              "not proof of malicious activity.\n";

    return true;
}

int main() {
    cout << "========================================\n";
    cout << " NETWORK TRAFFIC ANOMALY ANALYSER\n";
    cout << " OFFLINE CSV ANALYSIS - C++\n";
    cout << "========================================\n\n";

    cout << "This program analyses saved CSV data only.\n";
    cout << "It does not capture live network traffic.\n\n";

    string filename;

    cout << "Enter CSV filename (network_traffic.csv): ";
    getline(cin, filename);
    filename = trim(filename);

    if (filename.empty()) {
        cout << "Filename cannot be empty.\n";
        return 1;
    }

    vector<Packet> packets;

    if (!loadCSV(filename, packets)) {
        cout << "No records to analyse. Check your CSV file.\n";
        return 1;
    }

    vector<Alert> alerts = analyseTraffic(packets);

    cout << "\nANALYSIS SUMMARY\n";
    cout << "----------------\n";
    cout << "Records analysed: " << packets.size() << '\n';
    cout << "Alerts generated: " << alerts.size() << "\n\n";

    if (alerts.empty()) {
        cout << "No configured anomaly rules were triggered.\n";
    } else {
        for (size_t i = 0; i < alerts.size(); ++i) {
            cout << i + 1 << ". [" << alerts[i].type << "] "
                 << alerts[i].message << '\n';
        }
    }

    if (saveReport("traffic_report.txt", packets, alerts))
        cout << "\nReport saved as traffic_report.txt\n";

    cout << "Analysis complete.\n";
    return 0;
}

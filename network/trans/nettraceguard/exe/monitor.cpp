#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

struct GuardConfig
{
    uint32_t adapterIfIndex = 0;
    uint64_t adapterLuid = 0;
    uint32_t windowSeconds = 10;
    uint32_t icmpEchoThreshold = 10;
    uint32_t ddosAggregatePpsThreshold = 30;
    uint32_t ddosPerSourcePpsThreshold = 10;
    uint32_t ddosFanInThreshold = 8;
    uint32_t cooldownSeconds = 15;
    std::string failMode = "permit";
};

struct PacketRecord
{
    uint64_t timestampMs = 0;
    uint32_t adapterIfIndex = 0;
    std::string src;
    std::string dst;
    std::string protocol;
    uint32_t icmpType = 0;
    uint32_t bytes = 0;
};

struct Incident
{
    uint64_t timestampMs = 0;
    std::string severity;
    std::string attackType;
    std::string why;
    std::string action;
};

struct AnalysisResult
{
    uint64_t packetCount = 0;
    uint64_t byteCount = 0;
    std::map<std::string, uint64_t> protocolCount;
    std::unordered_map<std::string, uint64_t> sourceCount;
    std::unordered_map<std::string, uint64_t> destinationCount;
    std::vector<Incident> incidents;
};

static bool ParseUint64(const std::string& s, uint64_t& value)
{
    try
    {
        size_t idx = 0;
        value = std::stoull(s, &idx, 10);
        return idx == s.size();
    }
    catch (...)
    {
        return false;
    }
}

static bool ParseUint32(const std::string& s, uint32_t& value)
{
    uint64_t temp = 0;
    if (!ParseUint64(s, temp) || temp > 0xFFFFFFFFull)
    {
        return false;
    }

    value = static_cast<uint32_t>(temp);
    return true;
}

static std::vector<std::string> SplitCsvLine(const std::string& line)
{
    std::vector<std::string> out;
    std::stringstream ss(line);
    std::string token;
    while (std::getline(ss, token, ','))
    {
        out.push_back(token);
    }
    return out;
}

static bool LoadPackets(const std::string& inputCsv, std::vector<PacketRecord>& packets)
{
    std::ifstream in(inputCsv);
    if (!in)
    {
        std::cerr << "Failed to open trace file: " << inputCsv << "\n";
        return false;
    }

    std::string line;
    uint64_t lineNo = 0;
    while (std::getline(in, line))
    {
        ++lineNo;
        if (line.empty())
        {
            continue;
        }

        if (lineNo == 1 && line.find("timestampMs") != std::string::npos)
        {
            continue;
        }

        auto cols = SplitCsvLine(line);
        if (cols.size() < 7)
        {
            std::cerr << "Skipping malformed CSV line " << lineNo << "\n";
            continue;
        }

        PacketRecord p;
        if (!ParseUint64(cols[0], p.timestampMs) || !ParseUint32(cols[1], p.adapterIfIndex) ||
            !ParseUint32(cols[5], p.icmpType) || !ParseUint32(cols[6], p.bytes))
        {
            std::cerr << "Skipping invalid numeric values at line " << lineNo << "\n";
            continue;
        }

        p.src = cols[2];
        p.dst = cols[3];
        p.protocol = cols[4];
        packets.push_back(std::move(p));
    }

    return true;
}

static bool LoadConfig(const std::string& path, GuardConfig& cfg)
{
    std::ifstream in(path);
    if (!in)
    {
        return false;
    }

    std::stringstream ss;
    ss << in.rdbuf();
    std::string content = ss.str();

    auto ReadNumeric = [&](const std::string& key, uint64_t& target) {
        const std::string marker = "\"" + key + "\"";
        auto pos = content.find(marker);
        if (pos == std::string::npos)
        {
            return;
        }

        pos = content.find(':', pos);
        if (pos == std::string::npos)
        {
            return;
        }

        ++pos;
        while (pos < content.size() && std::isspace(static_cast<unsigned char>(content[pos])))
        {
            ++pos;
        }

        size_t end = pos;
        while (end < content.size() && std::isdigit(static_cast<unsigned char>(content[end])))
        {
            ++end;
        }

        uint64_t value = 0;
        if (end > pos && ParseUint64(content.substr(pos, end - pos), value))
        {
            target = value;
        }
    };

    uint64_t temp = 0;
    ReadNumeric("adapterIfIndex", temp); cfg.adapterIfIndex = static_cast<uint32_t>(temp);
    ReadNumeric("adapterLuid", temp); cfg.adapterLuid = temp;
    ReadNumeric("windowSeconds", temp); cfg.windowSeconds = static_cast<uint32_t>(temp);
    ReadNumeric("icmpEchoThreshold", temp); cfg.icmpEchoThreshold = static_cast<uint32_t>(temp);
    ReadNumeric("ddosAggregatePpsThreshold", temp); cfg.ddosAggregatePpsThreshold = static_cast<uint32_t>(temp);
    ReadNumeric("ddosPerSourcePpsThreshold", temp); cfg.ddosPerSourcePpsThreshold = static_cast<uint32_t>(temp);
    ReadNumeric("ddosFanInThreshold", temp); cfg.ddosFanInThreshold = static_cast<uint32_t>(temp);
    ReadNumeric("cooldownSeconds", temp); cfg.cooldownSeconds = static_cast<uint32_t>(temp);

    const std::string failModeKey = "\"failMode\"";
    auto failPos = content.find(failModeKey);
    if (failPos != std::string::npos)
    {
        failPos = content.find(':', failPos);
        if (failPos != std::string::npos)
        {
            auto quoteStart = content.find('"', failPos + 1);
            if (quoteStart != std::string::npos)
            {
                auto quoteEnd = content.find('"', quoteStart + 1);
                if (quoteEnd != std::string::npos)
                {
                    cfg.failMode = content.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                }
            }
        }
    }

    return true;
}

static bool SaveConfig(const std::string& path, const GuardConfig& cfg)
{
    std::ofstream out(path);
    if (!out)
    {
        return false;
    }

    out << "{\n"
        << "  \"adapterIfIndex\": " << cfg.adapterIfIndex << ",\n"
        << "  \"adapterLuid\": " << cfg.adapterLuid << ",\n"
        << "  \"windowSeconds\": " << cfg.windowSeconds << ",\n"
        << "  \"icmpEchoThreshold\": " << cfg.icmpEchoThreshold << ",\n"
        << "  \"ddosAggregatePpsThreshold\": " << cfg.ddosAggregatePpsThreshold << ",\n"
        << "  \"ddosPerSourcePpsThreshold\": " << cfg.ddosPerSourcePpsThreshold << ",\n"
        << "  \"ddosFanInThreshold\": " << cfg.ddosFanInThreshold << ",\n"
        << "  \"cooldownSeconds\": " << cfg.cooldownSeconds << ",\n"
        << "  \"failMode\": \"" << cfg.failMode << "\"\n"
        << "}\n";

    return true;
}

static void PushIncident(
    AnalysisResult& result,
    uint64_t timestampMs,
    const std::string& severity,
    const std::string& attackType,
    const std::string& why,
    const std::string& action,
    std::unordered_map<std::string, uint64_t>& lastIncidentMs,
    uint32_t cooldownSeconds)
{
    auto it = lastIncidentMs.find(attackType);
    if (it != lastIncidentMs.end() && timestampMs < (it->second + static_cast<uint64_t>(cooldownSeconds) * 1000ull))
    {
        return;
    }

    lastIncidentMs[attackType] = timestampMs;
    result.incidents.push_back(Incident{ timestampMs, severity, attackType, why, action });
}

static AnalysisResult Analyze(const std::vector<PacketRecord>& packets, const GuardConfig& cfg)
{
    AnalysisResult result;

    std::deque<uint64_t> icmpWindow;
    std::deque<uint64_t> aggregateWindow;
    std::unordered_map<std::string, std::deque<uint64_t>> sourceWindows;
    std::unordered_map<std::string, uint64_t> sourceWindowCount;
    std::unordered_map<std::string, uint64_t> lastIncidentMs;

    const uint64_t windowMs = static_cast<uint64_t>(cfg.windowSeconds) * 1000ull;

    for (const auto& p : packets)
    {
        if (cfg.adapterIfIndex != 0 && p.adapterIfIndex != cfg.adapterIfIndex)
        {
            continue;
        }

        ++result.packetCount;
        result.byteCount += p.bytes;
        ++result.protocolCount[p.protocol];
        ++result.sourceCount[p.src];
        ++result.destinationCount[p.dst];

        aggregateWindow.push_back(p.timestampMs);
        while (!aggregateWindow.empty() && p.timestampMs - aggregateWindow.front() > windowMs)
        {
            aggregateWindow.pop_front();
        }

        auto& srcWindow = sourceWindows[p.src];
        srcWindow.push_back(p.timestampMs);
        while (!srcWindow.empty() && p.timestampMs - srcWindow.front() > windowMs)
        {
            srcWindow.pop_front();
        }

        if (p.protocol == "ICMP" && p.icmpType == 8)
        {
            icmpWindow.push_back(p.timestampMs);
            while (!icmpWindow.empty() && p.timestampMs - icmpWindow.front() > windowMs)
            {
                icmpWindow.pop_front();
            }

            if (icmpWindow.size() >= cfg.icmpEchoThreshold)
            {
                PushIncident(
                    result,
                    p.timestampMs,
                    "high",
                    "icmp_flood",
                    "High-rate ICMP echo requests exceeded threshold within sampling window.",
                    "Rate-limit echo traffic on selected adapter and inspect dominant sources.",
                    lastIncidentMs,
                    cfg.cooldownSeconds);
            }
        }

        if (srcWindow.size() >= cfg.ddosPerSourcePpsThreshold)
        {
            PushIncident(
                result,
                p.timestampMs,
                "medium",
                "per_source_spike",
                "Single source packet-rate exceeded per-source DDoS threshold.",
                "Apply temporary block/rate-limit policy for source and validate legitimacy.",
                lastIncidentMs,
                cfg.cooldownSeconds);
        }

        if (aggregateWindow.size() >= cfg.ddosAggregatePpsThreshold)
        {
            std::set<std::string> distinctSources;
            for (const auto& sourcePair : sourceWindows)
            {
                if (!sourcePair.second.empty())
                {
                    distinctSources.insert(sourcePair.first);
                }
            }

            if (distinctSources.size() >= cfg.ddosFanInThreshold)
            {
                PushIncident(
                    result,
                    p.timestampMs,
                    "critical",
                    "distributed_flood",
                    "Aggregate packet-rate and source fan-in exceeded DDoS thresholds.",
                    "Enable fail-" + cfg.failMode + " policy, isolate adapter, and trigger incident response.",
                    lastIncidentMs,
                    cfg.cooldownSeconds);
            }
        }
    }

    return result;
}

static std::vector<std::pair<std::string, uint64_t>> TopN(const std::unordered_map<std::string, uint64_t>& input, size_t n)
{
    std::vector<std::pair<std::string, uint64_t>> entries(input.begin(), input.end());
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    if (entries.size() > n)
    {
        entries.resize(n);
    }

    return entries;
}

static bool WriteJsonReport(const std::string& jsonPath, const AnalysisResult& result)
{
    std::ofstream out(jsonPath);
    if (!out)
    {
        return false;
    }

    out << "{\n";
    out << "  \"summary\": {\n";
    out << "    \"packets\": " << result.packetCount << ",\n";
    out << "    \"bytes\": " << result.byteCount << "\n";
    out << "  },\n";

    out << "  \"protocolBreakdown\": {";
    bool first = true;
    for (const auto& protocol : result.protocolCount)
    {
        if (!first) out << ", ";
        out << "\"" << protocol.first << "\": " << protocol.second;
        first = false;
    }
    out << "},\n";

    out << "  \"incidents\": [\n";
    for (size_t i = 0; i < result.incidents.size(); ++i)
    {
        const auto& inc = result.incidents[i];
        out << "    {\n";
        out << "      \"timestampMs\": " << inc.timestampMs << ",\n";
        out << "      \"severity\": \"" << inc.severity << "\",\n";
        out << "      \"type\": \"" << inc.attackType << "\",\n";
        out << "      \"why\": \"" << inc.why << "\",\n";
        out << "      \"recommendedAction\": \"" << inc.action << "\"\n";
        out << "    }" << (i + 1 == result.incidents.size() ? "" : ",") << "\n";
    }
    out << "  ]\n";
    out << "}\n";

    return true;
}

static bool WriteTextReport(const std::string& textPath, const AnalysisResult& result)
{
    std::ofstream out(textPath);
    if (!out)
    {
        return false;
    }

    out << "NetTraceGuard Analysis Summary\n";
    out << "=============================\n";
    out << "Packets analyzed: " << result.packetCount << "\n";
    out << "Bytes analyzed:   " << result.byteCount << "\n\n";

    out << "Protocol breakdown:\n";
    for (const auto& protocol : result.protocolCount)
    {
        out << "  - " << protocol.first << ": " << protocol.second << "\n";
    }

    out << "\nTop sources:\n";
    for (const auto& source : TopN(result.sourceCount, 5))
    {
        out << "  - " << source.first << ": " << source.second << " packets\n";
    }

    out << "\nTop destinations:\n";
    for (const auto& dest : TopN(result.destinationCount, 5))
    {
        out << "  - " << dest.first << ": " << dest.second << " packets\n";
    }

    out << "\nIncident timeline:\n";
    if (result.incidents.empty())
    {
        out << "  - no incidents detected\n";
    }
    else
    {
        for (const auto& inc : result.incidents)
        {
            out << "  - [" << inc.timestampMs << "ms] " << inc.severity << " " << inc.attackType
                << " | " << inc.why << " | Action: " << inc.action << "\n";
        }
    }

    return true;
}

static void PrintUsage()
{
    std::cout
        << "NetTraceGuard control and analysis utility\n\n"
        << "Commands:\n"
        << "  configure --config <path> [--adapter-ifindex N] [--adapter-luid N] [--window-sec N]"
        << " [--icmp-threshold N] [--ddos-aggregate-threshold N] [--ddos-per-source-threshold N]"
        << " [--ddos-fanin-threshold N] [--cooldown-sec N] [--fail-mode permit|block]\n"
        << "  analyze --config <path> --input <trace.csv> --json <report.json> --text <report.txt>\n"
        << "  dashboard --config <path> --input <trace.csv>\n\n"
        << "CSV format:\n"
        << "  timestampMs,adapterIfIndex,src,dst,protocol,icmpType,bytes\n";
}

static std::string GetArg(int argc, char** argv, int& i)
{
    if (i + 1 >= argc)
    {
        return {};
    }

    ++i;
    return argv[i];
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        PrintUsage();
        return 1;
    }

    const std::string command = argv[1];

    if (command == "configure")
    {
        GuardConfig cfg;
        std::string configPath;

        for (int i = 2; i < argc; ++i)
        {
            const std::string key = argv[i];
            std::string value;

            if (key == "--config")
            {
                configPath = GetArg(argc, argv, i);
            }
            else if (key == "--adapter-ifindex")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.adapterIfIndex);
            }
            else if (key == "--adapter-luid")
            {
                value = GetArg(argc, argv, i);
                ParseUint64(value, cfg.adapterLuid);
            }
            else if (key == "--window-sec")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.windowSeconds);
            }
            else if (key == "--icmp-threshold")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.icmpEchoThreshold);
            }
            else if (key == "--ddos-aggregate-threshold")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.ddosAggregatePpsThreshold);
            }
            else if (key == "--ddos-per-source-threshold")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.ddosPerSourcePpsThreshold);
            }
            else if (key == "--ddos-fanin-threshold")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.ddosFanInThreshold);
            }
            else if (key == "--cooldown-sec")
            {
                value = GetArg(argc, argv, i);
                ParseUint32(value, cfg.cooldownSeconds);
            }
            else if (key == "--fail-mode")
            {
                cfg.failMode = GetArg(argc, argv, i);
            }
        }

        if (configPath.empty())
        {
            std::cerr << "Missing --config\n";
            return 1;
        }

        if (!SaveConfig(configPath, cfg))
        {
            std::cerr << "Failed to write config to " << configPath << "\n";
            return 1;
        }

        std::cout << "Saved configuration to " << configPath << "\n";
        return 0;
    }

    if (command == "analyze" || command == "dashboard")
    {
        GuardConfig cfg;
        std::string configPath;
        std::string inputPath;
        std::string jsonPath;
        std::string textPath;

        for (int i = 2; i < argc; ++i)
        {
            const std::string key = argv[i];
            if (key == "--config")
            {
                configPath = GetArg(argc, argv, i);
            }
            else if (key == "--input")
            {
                inputPath = GetArg(argc, argv, i);
            }
            else if (key == "--json")
            {
                jsonPath = GetArg(argc, argv, i);
            }
            else if (key == "--text")
            {
                textPath = GetArg(argc, argv, i);
            }
        }

        if (configPath.empty() || inputPath.empty())
        {
            std::cerr << "Missing --config or --input\n";
            return 1;
        }

        if (!LoadConfig(configPath, cfg))
        {
            std::cerr << "Failed to read config from " << configPath << "\n";
            return 1;
        }

        std::vector<PacketRecord> packets;
        if (!LoadPackets(inputPath, packets))
        {
            return 1;
        }

        auto result = Analyze(packets, cfg);

        std::cout << "Packets analyzed: " << result.packetCount << "\n";
        std::cout << "Incidents: " << result.incidents.size() << "\n";

        if (command == "analyze")
        {
            if (jsonPath.empty() || textPath.empty())
            {
                std::cerr << "Missing --json or --text\n";
                return 1;
            }

            if (!WriteJsonReport(jsonPath, result) || !WriteTextReport(textPath, result))
            {
                std::cerr << "Failed to write output reports\n";
                return 1;
            }

            std::cout << "Wrote reports: " << jsonPath << " and " << textPath << "\n";
        }
        else
        {
            std::cout << "Top sources:\n";
            for (const auto& source : TopN(result.sourceCount, 5))
            {
                std::cout << "  " << std::setw(18) << source.first << " : " << source.second << "\n";
            }

            std::cout << "Incident timeline:\n";
            for (const auto& inc : result.incidents)
            {
                std::cout << "  [" << inc.timestampMs << "ms] " << inc.severity << " " << inc.attackType << "\n";
                std::cout << "    Why: " << inc.why << "\n";
                std::cout << "    Action: " << inc.action << "\n";
            }
        }

        return 0;
    }

    PrintUsage();
    return 1;
}

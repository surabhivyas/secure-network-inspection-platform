#ifndef MODELS_H
#define MODELS_H

#include <cstddef>
#include <string>

struct RequestRecord {
    std::string user;
    std::string role;
    std::string source_ip;
    std::string destination_domain;
    std::string protocol;
    int port;
    bool encrypted;
    std::string file_name;
    std::string file_type;
    std::size_t payload_size;
    bool from_packet_capture;
    std::string payload_content;
};

struct Finding {
    std::string rule_name;
    std::string description;
    int severity; // 1 (low) - 10 (high)
};

struct FeatureSummary {
    int is_insecure_protocol = 0;
    int is_risky_file = 0;
    int is_large_payload = 0;
    int is_suspicious_domain = 0;
    int is_privileged_execution_risk = 0;
    int is_admin = 0;
    int is_unencrypted = 0;
    int is_data_exfiltration = 0;
    int is_ioc_match = 0;
};

struct ScoreResult {
    double risk_score = 0.0;
    double confidence = 0.0;
    bool success =  false;
};

#endif 

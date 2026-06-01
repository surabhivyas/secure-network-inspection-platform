#include "rule_engine.h"
#include <string>
#include<fstream>
#include<unordered_set>

static bool contains_sensitive_data(const std:: string& content) {
    if(content.find("API_KEY") != std::string::npos) {
        return true;
    }

    if(content.find("@") != std::string::npos) {
        return true;
    }

    if(content.find("CONFIDENTIAL") != std::string::npos) {
        return true;
    }

    if(content.find("4111-") != std::string::npos) {
        return true;
    }

    return false;


}

static std::unordered_set<std::string> load_iocs(const std::string& filename) {
    std::unordered_set<std::string> iocs;

    std::ifstream file(filename);

    std::string line;

    while (std::getline(file, line)) {
        if (!line.empty()) {
            iocs.insert(line);
        }
    }

    return iocs;
}   
 
std::vector<Finding> evaluate_rules(const RequestRecord& req){
    std::vector<Finding> findings;

    static auto malicious_domains =
        load_iocs("../data/malicious_domains.txt");

    static auto malicious_ips =
        load_iocs("../data/malicious_ips.txt"); 
   
    //Rule 1: Insecure protocol
    if(req.protocol == "HTTP" && !req.encrypted){
        findings.push_back({
            "INSECURE_PROTOCOL",
            "Traffic is unencrypted over HTTP",
             7
        });
     }

    //Rule 2: Suspicious file type
    if(req.file_type == "exe" || req.file_type == "sh" || req.file_type == "js" || req.file_type == "bat"){
        findings.push_back({
            "EXECUTABLE_DOWNLOAD",
            "Risky executable or script file detected in transfer",
             8
        });
     }

     //Rule 3: Large payload
     if(req.payload_size >  1024 * 1024){ // >1MB
        findings.push_back({
            "LARGE_PAYLOAD",
            "Large payload size may indicate data exfiltration",
             5
        });
     }

    //Rule 4: Suspicious domain (basic heuristic)
     if(req.destination_domain.find("unknown") !=  std::string::npos){
        findings.push_back({
            "SUSPICIOUS_DOMAIN",
            "Domain appears untrusted or unknown",
             6
        });
     }

    //Rule 5: Admin downlaoding executable (high risk combo)
     if(req.role == "admin" && req.file_type == "exe"){
        findings.push_back({
            "PRIVILEGED_EXECUTION_RISK",
            "Admin user downloading executable content",
             9
        });
     }

    if(contains_sensitive_data(req.payload_content)) {
        findings.push_back({
            "DLP_DATA_EXFILTRATION",
            "Sensitive data detected in payload content",
            9
        });
    }
    
    if (malicious_domains.count(req.destination_domain) || malicious_ips.count(req.source_ip)) {

        findings.push_back({
            "IOC_MATCH_DETECTED",
            "Matched known malicious IOC",
            10
        });
    }
      
    return findings;

}

FeatureSummary extract_features(const RequestRecord& req, const std::vector<Finding>& findings) {
    FeatureSummary features;

    if(req.role == "admin"){
        features.is_admin = 1;
    }

    if (!req.encrypted){
        features.is_unencrypted = 1;
    }

    for(const auto& finding : findings) {
        if(finding.rule_name == "INSECURE_PROTOCOL"){
            features.is_insecure_protocol = 1;
        }else if(finding.rule_name == "EXECUTABLE_DOWNLOAD"){
            features.is_risky_file = 1;
        }else if(finding.rule_name == "LARGE_PAYLOAD"){
            features.is_large_payload = 1;
        }else if(finding.rule_name == "SUSPICIOUS_DOMAIN"){
            features.is_suspicious_domain = 1;
        }else if(finding.rule_name == "PRIVILEGED_EXECUTION_RISK"){
            features.is_privileged_execution_risk = 1;
        }else if(finding.rule_name == "DLP_DATA_EXFILTRATION") {
            features.is_data_exfiltration = 1;
        }else if (finding.rule_name == "IOC_MATCH_DETECTED") {
            features.is_ioc_match = 1;
        }
    }
    
    return features;
}


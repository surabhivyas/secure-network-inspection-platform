#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>

#include "models.h"
#include "rule_engine.h"

static void print_request(const RequestRecord& req) {
    std::cout << "=== Request Summary ===\n";
    std::cout << "User: " << req.user << '\n';
    std::cout << "Role: " << req.role << '\n'; 
    std::cout << "Source IP: " << req.source_ip << '\n';
    std::cout << "Destination Domain: " << req.destination_domain << '\n';
    std::cout << "Protocol: " << req.protocol << '\n';
    std::cout << "Port: " << req.port << '\n';
    std::cout << "Encrypted: " << (req.encrypted ? "Yes" : "No") << '\n';
    std::cout << "File Name: " << req.file_name << '\n';
    std::cout << "File Type: " << req.file_type << '\n';
    std::cout << "Payload Size: " << req.payload_size << "  bytes\n";
    std::cout << "Input Source: " << (req.from_packet_capture ? "Packet Capture" : "Simulated Request") << '\n';

}

static void print_findings(const std::vector<Finding>& findings){
    std::cout << "\n=== Security Findings ===\n";
    
    if(findings.empty()){
        std::cout << "No issues detected. \n";
        return;
    }
    
    for(const auto& f : findings){
        std::cout << "[Rule] " << f.rule_name << "\n";
        std::cout << "Description: " << f.description << "\n";
        std::cout << "Severity:  " << f.severity << "\n\n";
    }
}

static void print_features(const FeatureSummary& features){
    std::cout << "=== Feature Summary=== \n";
    std::cout << "is_insecure_protocol: " << features.is_insecure_protocol << '\n';
    std::cout << "is_risky_file: " << features.is_risky_file << '\n'; 
    std::cout << "is_large_payload: " << features.is_large_payload << '\n';   
    std::cout << "is_suspicious_domain: " << features.is_suspicious_domain << '\n';
    std::cout << "is_privileged_execution_risk: " << features.is_privileged_execution_risk << '\n';
    std::cout << "is_admin: " << features.is_admin << '\n';
    std::cout << "is_unencrypted: " << features.is_unencrypted << '\n';
    std::cout << "is_data_exfiltration: " << features.is_data_exfiltration << '\n';
    std::cout << "is_ioc_match: " << features.is_ioc_match << '\n';
}

void write_features_to_file(const FeatureSummary& features, const std:: string& filename){
    std::ofstream out(filename);
    
    out << "is_insecure_protocol=" << features.is_insecure_protocol << "\n";
    out << "is_risky_file=" << features.is_risky_file << "\n";
    out << "is_large_payload=" << features.is_large_payload << "\n";
    out << "is_suspicious_domain=" << features.is_suspicious_domain << "\n";
    out << "is_privileged_execution_risk=" << features.is_privileged_execution_risk << "\n";
    out << "is_admin=" << features.is_admin << "\n";
    out << "is_unencrypted=" << features.is_unencrypted << "\n";
    out << "is_data_exfiltration=" << features.is_data_exfiltration << "\n";
    out << "is_ioc_match=" << features.is_ioc_match << "\n";
}

static ScoreResult run_python_scorer(const std::string& feature_file){
    ScoreResult result;

    std::string command = "python3 ../ai/score.py " + feature_file;
    FILE* pipe = popen (command.c_str(), "r");

    if(!pipe){
        std::cerr << "Failed to run python scorer.\n";
        return result;
    }

    char buffer[256];
    std::string output;

    while(fgets(buffer, sizeof(buffer), pipe) != nullptr){
        output += buffer;
    }

    pclose(pipe);

    std::stringstream stream(output);
    std::string line;
  
    while(std::getline(stream, line)){
        if(line.rfind("RISK_SCORE", 0) == 0){
            result.risk_score = std::stod(line.substr(std::string("RISK_SCORE=").size()));
        }else if (line.rfind("CONFIDENCE", 0) == 0){
            result.confidence = std::stod(line.substr(std::string("CONFIDENCE=").size()));
        }
    }

    result.success = true;
    return result;

}

static std::string make_decision(const FeatureSummary& features, double risk_score){
    if(features.is_data_exfiltration){
        return "BLOCK";
    }

    if(risk_score > 0.75){
        return "BLOCK";
    }
    if(risk_score >= 0.35){
        return "ALERT";
    } 
    return "ALLOW";
}

struct InspectionResult {
    int record_id;
    std::string user;
    std::string source_ip;
    std::string destination_domain;
    std::string decision;
    double risk_score;
    double confidence;
    std::vector<std::string> findings;
};

InspectionResult process_request(const RequestRecord& req, const std::string& feature_file, int record_id){
    print_request(req);

    auto findings = evaluate_rules(req);
    print_findings(findings);

    auto features = extract_features(req, findings);
    print_features(features);

    write_features_to_file(features, feature_file);
    
    ScoreResult score = run_python_scorer(feature_file);

    std::cout <<"\n ===AI-Inspired Score===\n";
    if (score.success){
        std::cout << "Risk Score: " << score.risk_score << '\n';
        std::cout << "Confidence: " << score.confidence << '\n';
    }else {
        std::cout << "Scoring failed\n";
    }
   
    std::string decision = make_decision(features, score.risk_score); 
   
    InspectionResult result;
    result.record_id = record_id;
    result.user = req.user;
    result.source_ip = req.source_ip;
    result.destination_domain = req.destination_domain;
    result.decision = decision;
    result.risk_score = score.risk_score;
    result.confidence = score.confidence;

    for (const auto& finding : findings) {
        result.findings.push_back(finding.rule_name);
    }
     
    std::cout << "\n === Final Decision ===\n";
    std::cout << "Action:" << decision << "\n";

    std::cout << "\n-------------------------------------------\n\n";
   
    return result;
}

static std::vector<RequestRecord>load_requests_from_file(const std::string& filename){
    
    std::vector<RequestRecord> requests;
    std::ifstream file(filename);

    if(!file) {
        std::cerr << "Failed to open traffic file \n";
        return requests;
    }
 
    std::string line;

    while(std::getline(file, line)) {
 
        if(line.empty()) {
            continue;
        }
        
        std::stringstream ss(line);
     
        std::vector<std::string> fields;
       
        std::string field;

        while(std::getline(ss, field, ',')) {
            fields.push_back(field);
        }

        if(fields.size() != 11) {
            std::cerr << "Invalid traffic record skipped\n";
            continue;
        }
    
        RequestRecord req{
            fields[0],                    //user
            fields[1],                    //role
            fields[2],                    //source_ip
            fields[3],                    //destination_domain
            fields[4],                    //protocol
            std::stoi(fields[5]),         //port
            fields[6] == "1",             //encrypted
            fields[7],                    //file_name
            fields[8],                    //file_type
            static_cast<size_t>(std::stoi(fields[9])),         //payload_size
            false,                        //privileged_execution
            fields[10]                    //payload_content
        };
 
        requests.push_back(req);
    }
    
    return requests;
}

std::mutex output_mutex;
std::mutex results_mutex;
std::vector<InspectionResult> inspection_results;

void threaded_process_request(const RequestRecord& req, int record_number) {
    InspectionResult result;

    {
        std::lock_guard<std::mutex> lock(output_mutex);

        std::cout << "\n========== TRAFFIC RECORD "
                  << record_number
                  << " ==========\n";

        result = process_request(req, "features.txt", record_number);
   }

   {
       std::lock_guard<std::mutex> lock(results_mutex);
       inspection_results.push_back(result);
   }
}

void write_results_to_json(const std::vector<InspectionResult>& results, const std::string& filename) {
    std::ofstream out(filename);

    int total_records = results.size();
    int allowed = 0;
    int blocked = 0;
    int alerted = 0;
    int dlp_events = 0;
    int ioc_matches = 0;

    for (const auto& r : results) {
        if (r.decision == "ALLOW") {
            allowed++;
        } else if (r.decision == "BLOCK") {
            blocked++;
        } else if (r.decision == "ALERT") {
            alerted++;
        }

        for (const auto& finding : r.findings) {
            if (finding == "DLP_DATA_EXFILTRATION") {
                dlp_events++;
            } else if (finding == "IOC_MATCH_DETECTED") {
                ioc_matches++;
            }
        }
    }


    out << "{\n";
    out << " \"summary\": {\n";
    out << " \"total_records\": " << total_records << ",\n";
    out << " \"allowed\": " << allowed << ",\n";
    out << " \"alerted\": " << alerted << ",\n";
    out << " \"blocked\": " << blocked << ",\n";
    out << " \"dlp_events\": " << dlp_events << ",\n";
    out << " \"ioc_matches\": " << ioc_matches << "\n";
    out << " },\n";
    out << " \"results\": [\n";

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];

        out << " {\n";
        out << " \"record_id\": " << r.record_id << ",\n";
        out << " \"user\": \"" << r.user << "\",\n";
        out << " \"source_ip\": \"" << r.source_ip << "\",\n";
        out << " \"destination_domain\": \"" << r.destination_domain << "\",\n";
        out << " \"decision\": \"" << r.decision << "\",\n";
        out << " \"risk_score\": " << r.risk_score << ",\n";
        out << " \"confidence\": " << r.confidence << ",\n";

        out << " \"findings\": [";
        for (size_t j = 0; j < r.findings.size(); ++j) {
            out << "\"" << r.findings[j] << "\"";
            if (j + 1 < r.findings.size()) {
                out << ", ";
            }
        }
        out << "]\n";

        out << " }";

        if (i + 1 < results.size()) {
            out << ",";
        }

        out << "\n";
    }

    out << " ]\n";
    out << "}\n";
}

int main() {
    
    // High Risk Case
    /*RequestRecord high_risk{
        "admin_user",
        "admin",
        "10.10.1.25",
        "unknown-download.example",
        "HTTP",
        80,
        false,
        "payload.exe",
        "exe",
        5242880,
        false
    };
  
    RequestRecord medium_risk{
        "user2",
        "user",
        "10.1.1.2",
        "unknown-site.com",
        "HTTPS",
        443,
        true,
        "script.sh",
        "sh",
        200000,
        false
    };
    
    RequestRecord benign{
        "user1",
        "user",
        "10.1.1.1",
        "trusted.com",
        "HTTPS",
        443,
        true,
        "report.pdf",
        "pdf",
        50000,
        false,
        "Quarterly report summary"
    };
   
    RequestRecord dlp_case{
        "user3",
        "user",
        "10.1.1.3",
        "trusted.com",
        "HTTPS",
        443,
        true,
        "customer_export.txt",
        "txt",
        120000,
        false,
        "Customer export contains email user@example.com and API_KEY=abc123"
    };

    RequestRecord ioc_case{
        "user4",
        "user",
        "192.168.100.50",
        "evil.com",
        "HTTPS",
        443,
        true,
        "normal.txt",
        "txt",
        1000,
        false,
        "Regular payload"
    };

    std::cout << "===============BENIGN CASE=================\n";
    process_request(benign, "features_benign.txt");

    std::cout << "===============MEDIUM RISK CASE=================\n";
    process_request(medium_risk,"features_medium.txt");
    
    std::cout << "===============HIGH RISK CASE=================\n";
    process_request(high_risk,"features_high.txt");

    std::cout << "===============DLP CASE======================\n";
    process_request(dlp_case, "features_dlp.txt");

    std::cout << "\n========== IOC CASE ==========\n";
    process_request(ioc_case, "features_ioc.txt");*/

    auto requests = load_requests_from_file("../data/traffic_samples.txt");

    std::vector<std::thread> workers;

    int counter = 1;

    for (const auto& req : requests) {
        
        workers.emplace_back(threaded_process_request,req, counter++);

    }
  
    for(auto& worker : workers){
        worker.join();
    }

    write_results_to_json(
        inspection_results,
        "../inspection_results.json"
    );

    return 0;
}   

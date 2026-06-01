#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include "models.h"
#include <vector>

std::vector<Finding> evaluate_rules(const RequestRecord& req);
FeatureSummary extract_features(const RequestRecord& req, const std::vector<Finding>& findings);

#endif

//
//  stun_test.h
//  WebRTC_Demo
//
//  Created by hr on 2025/12/3.
//  Copyright © 2025 jspp.com. All rights reserved.
//
#pragma once
#include <set>
#include <string>
#include <utility>
#include <vector>

std::string QueryFastestStun(const std::set<std::string>& servers, int timeoutMs, std::string* clientIp = nullptr);
std::vector<std::pair<std::string, int>> SortStun(const std::set<std::string>& servers, int timeoutMs, std::string* clientIp = nullptr);
std::string FindBestNode(const std::vector<std::pair<std::string, int>>& rtts1, std::vector<std::pair<std::string, int>> rtts2);

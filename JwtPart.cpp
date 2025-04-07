//
// Created by sigsegv on 12/31/23.
//

#include "include/JwtPart.h"
#include <nlohmann/json.hpp>
#include "include/Base64.h"

class JwtPartValue : public JwtPartGenericValue {
public:
    virtual ~JwtPartValue() = default;
    virtual void AddToJson(nlohmann::json &obj, const std::string &name) const = 0;
    virtual void AddToJson(nlohmann::json &obj) const = 0;
    std::vector<std::shared_ptr<JwtPartGenericValue>> GetArrayItems() override;
    std::map<std::string, std::shared_ptr<JwtPartGenericValue>> GetObjectItems() override;
    std::string GetString() override;
    int64_t GetInteger() override;
};

std::vector<std::shared_ptr<JwtPartGenericValue>> JwtPartValue::GetArrayItems() {
    return {};
}

std::map<std::string, std::shared_ptr<JwtPartGenericValue>> JwtPartValue::GetObjectItems() {
    return {};
}

std::string JwtPartValue::GetString() {
    return {};
}

int64_t JwtPartValue::GetInteger() {
    return 0;
}

class JwtPartJsonValue : public JwtPartValue {
public:
    [[nodiscard]] virtual nlohmann::json ToJson() const = 0;
    void AddToJson(nlohmann::json &obj, const std::string &name) const override;
    void AddToJson(nlohmann::json &obj) const override;
};

class JwtPartObjectValue : public JwtPartJsonValue {
private:
    std::map<std::string,std::shared_ptr<JwtPartValue>> map;
public:
    JwtPartObjectValue(const nlohmann::json &json);
    JwtPartObjectValue(const std::map<std::string,std::shared_ptr<JwtPartValue>> &map) : map(map) {}
    std::map<std::string, std::shared_ptr<JwtPartGenericValue>> GetObjectItems() override;
    [[nodiscard]] nlohmann::json ToJson() const override;
    std::string ToJsonStr() const override;
};

class JwtPartArrayValue : public JwtPartJsonValue {
private:
    std::vector<std::shared_ptr<JwtPartValue>> vec;
public:
    JwtPartArrayValue(const nlohmann::json &json);
    JwtPartArrayValue(const std::vector<std::shared_ptr<JwtPartValue>> &vec) : vec(vec) {}
    std::vector<std::shared_ptr<JwtPartGenericValue>> GetArrayItems() override;
    [[nodiscard]] nlohmann::json ToJson() const override;
    std::string ToJsonStr() const override;
};

class JwtPartStringValue : public JwtPartValue {
    friend JwtPart;
private:
    std::string str;
public:
    JwtPartStringValue(const std::string &str) : str(str) {}
    std::string GetString() override;
    void AddToJson(nlohmann::json &obj, const std::string &name) const override;
    void AddToJson(nlohmann::json &obj) const override;
    std::string ToJsonStr() const override;
};

class JwtPartIntegerValue : public JwtPartValue {
    friend JwtPart;
private:
    int64_t integer;
public:
    JwtPartIntegerValue(int64_t integer) : integer(integer) {}
    int64_t GetInteger() override;
    void AddToJson(nlohmann::json &obj, const std::string &name) const override;
    void AddToJson(nlohmann::json &obj) const override;
    std::string ToJsonStr() const override;
};

void JwtPartJsonValue::AddToJson(nlohmann::json &obj, const std::string &name) const {
    auto json = ToJson();
    obj.emplace(name, json);
}

void JwtPartJsonValue::AddToJson(nlohmann::json &obj) const {
    auto json = ToJson();
    obj.emplace_back(json);
}

JwtPartObjectValue::JwtPartObjectValue(const nlohmann::json &json) : map() {
    if (json.is_object()) {
        for (const auto &prop : json.items()) {
            auto name = prop.key();
            auto value = prop.value();
            if (value.is_string()) {
                map.insert_or_assign(name, std::make_shared<JwtPartStringValue>(value));
            } else if (value.is_number_integer()) {
                map.insert_or_assign(name, std::make_shared<JwtPartIntegerValue>(value));
            } else if (value.is_object()) {
                map.insert_or_assign(name, std::make_shared<JwtPartObjectValue>(value));
            } else if (value.is_array()) {
                map.insert_or_assign(name, std::make_shared<JwtPartArrayValue>(value));
            }
        }
    }
}

std::map<std::string, std::shared_ptr<JwtPartGenericValue>> JwtPartObjectValue::GetObjectItems() {
    std::map<std::string, std::shared_ptr<JwtPartGenericValue>> result{};
    for (const auto &[name, value] : map) {
        result.insert_or_assign(name, value);
    }
    return result;
}

nlohmann::json JwtPartObjectValue::ToJson() const {
    nlohmann::json obj{};
    for (const auto &[name, value] : map) {
        value->AddToJson(obj, name);
    }
    return obj;
}

std::string JwtPartObjectValue::ToJsonStr() const {
    return ToJson().dump();
}

JwtPartArrayValue::JwtPartArrayValue(const nlohmann::json &json) : vec() {
    if (json.is_array()) {
        for (const auto &item : json) {
            if (item.is_string()) {
                vec.emplace_back(std::make_shared<JwtPartStringValue>(item));
            } else if (item.is_number_integer()) {
                vec.emplace_back(std::make_shared<JwtPartIntegerValue>(item));
            } else if (item.is_object()) {
                vec.emplace_back(std::make_shared<JwtPartObjectValue>(item));
            } else if (item.is_array()) {
                vec.emplace_back(std::make_shared<JwtPartArrayValue>(item));
            }
        }
    }
}

std::vector<std::shared_ptr<JwtPartGenericValue>> JwtPartArrayValue::GetArrayItems() {
    std::vector<std::shared_ptr<JwtPartGenericValue>> result{};
    for (const auto &item : vec) {
        result.emplace_back(item);
    }
    return result;
}

nlohmann::json JwtPartArrayValue::ToJson() const {
    nlohmann::json arr{};
    for (const auto &val : vec) {
        val->AddToJson(arr);
    }
    return arr;
}

std::string JwtPartArrayValue::ToJsonStr() const {
    return ToJson().dump();
}

std::string JwtPartStringValue::GetString() {
    return str;
}

void JwtPartStringValue::AddToJson(nlohmann::json &obj, const std::string &name) const {
    obj.emplace(name, str);
}

void JwtPartStringValue::AddToJson(nlohmann::json &obj) const {
    obj.emplace_back(str);
}

std::string JwtPartStringValue::ToJsonStr() const {
    nlohmann::json obj{str};
    return obj.dump();
}

int64_t JwtPartIntegerValue::GetInteger() {
    return integer;
}

void JwtPartIntegerValue::AddToJson(nlohmann::json &obj, const std::string &name) const {
    obj.emplace(name, integer);
}

void JwtPartIntegerValue::AddToJson(nlohmann::json &obj) const {
    obj.emplace_back(integer);
}

std::string JwtPartIntegerValue::ToJsonStr() const {
    return std::to_string(integer);
}

void JwtPartObject::Add(const std::string &name, const JwtPartObject &obj) {
    insert_or_assign(name, std::make_shared<JwtPartObjectValue>(obj));
}

void JwtPartObject::Add(const std::string &name, const std::string &str) {
    insert_or_assign(name, std::make_shared<JwtPartStringValue>(str));
}

void JwtPartArray::Add(const JwtPartObject &obj) {
    emplace_back(std::make_shared<JwtPartObjectValue>(obj));
}

JwtPart::JwtPart(const std::string &str) : JwtPart() {
    Base64UrlEncoding encoding{};
    nlohmann::json obj = nlohmann::json::parse(encoding.Decode(str));
    if (obj.is_object()) {
        for (const auto &prop: obj.items()) {
            std::string key = prop.key();
            auto value = prop.value();
            if (value.is_string()) {
                insert_or_assign(key, std::make_shared<JwtPartStringValue>(value));
            } else if (value.is_number_integer()) {
                insert_or_assign(key, std::make_shared<JwtPartIntegerValue>(value));
            } else if (value.is_array()) {
                insert_or_assign(key, std::make_shared<JwtPartArrayValue>(value));
            } else if (value.is_object()) {
                insert_or_assign(key, std::make_shared<JwtPartObjectValue>(value));
            }
        }
    }
}

std::string JwtPart::ToJson() const {
    nlohmann::json obj{};
    for (const auto &item : *this) {
        item.second->AddToJson(obj, item.first);
    }
    return obj.dump();
}

std::string JwtPart::ToBase64() const {
    auto json = ToJson();
    Base64UrlEncoding encoding{};
    return encoding.Encode(json);
}

void JwtPart::Add(const std::string &name, const std::string &value) {
    insert_or_assign(name, std::make_shared<JwtPartStringValue>(value));
}

void JwtPart::Add(const std::string &name, int64_t integer) {
    insert_or_assign(name, std::make_shared<JwtPartIntegerValue>(integer));
}

void JwtPart::Add(const std::string &name, const JwtPartArray &arr) {
    insert_or_assign(name, std::make_shared<JwtPartArrayValue>(arr));
}

void JwtPart::AddJsonObject(const std::string &name, const std::string &jsonObject) {
    insert_or_assign(name, std::make_shared<JwtPartObjectValue>(nlohmann::json::parse(jsonObject)));
}

std::string JwtPart::GetString(const std::string &name) {
    auto iterator = find(name);
    if (iterator != end()) {
        auto strValue = std::dynamic_pointer_cast<JwtPartStringValue>(iterator->second);
        if (strValue) {
            return strValue->str;
        }
    }
    return {};
}

int64_t JwtPart::GetInt(const std::string &name) {
    auto iterator = find(name);
    if (iterator != end()) {
        auto intValue = std::dynamic_pointer_cast<JwtPartIntegerValue>(iterator->second);
        if (intValue) {
            return intValue->integer;
        }
    }
    return {};
}

std::shared_ptr<JwtPartGenericValue> JwtPart::GetValue(const std::string &name) {
    auto iterator = find(name);
    if (iterator != end()) {
        return iterator->second;
    }
    return {};
}
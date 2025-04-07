//
// Created by sigsegv on 12/31/23.
//

#ifndef DRWHATSNOT_JWTPART_H
#define DRWHATSNOT_JWTPART_H

#include <map>
#include <vector>
#include <string>
#include <memory>

class JwtPartGenericValue {
public:
    virtual std::vector<std::shared_ptr<JwtPartGenericValue>> GetArrayItems() = 0;
    virtual std::map<std::string,std::shared_ptr<JwtPartGenericValue>> GetObjectItems() = 0;
    virtual std::string GetString() = 0;
    virtual int64_t GetInteger() = 0;
    virtual std::string ToJsonStr() const = 0;
};

class JwtPartValue;

class JwtPartObject : public std::map<std::string,std::shared_ptr<JwtPartValue>> {
public:
    void Add(const std::string &, const JwtPartObject &);
    void Add(const std::string &, const std::string &);
};

class JwtPartArray : public std::vector<std::shared_ptr<JwtPartValue>> {
public:
    void Add(const JwtPartObject &);
};

class JwtPart : public std::map<std::string,std::shared_ptr<JwtPartValue>> {
public:
    JwtPart() : std::map<std::string,std::shared_ptr<JwtPartValue>>() {}
    JwtPart(const std::string &);
    std::string ToJson() const;
    std::string ToBase64() const;
    void Add(const std::string &name, const std::string &value);
    void Add(const std::string &name, int64_t integer);
    void Add(const std::string &name, const JwtPartArray &);
    void AddJsonObject(const std::string &name, const std::string &jsonObject);
    std::string GetString(const std::string &name);
    int64_t GetInt(const std::string &name);
    std::shared_ptr<JwtPartGenericValue> GetValue(const std::string &name);
};


#endif //DRWHATSNOT_JWTPART_H

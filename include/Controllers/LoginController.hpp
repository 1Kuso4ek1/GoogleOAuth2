#pragma once
#include <drogon/HttpController.h>

using namespace drogon;

using Callback = std::function<void(const HttpResponsePtr&)>;

namespace Controllers
{

class LoginController final : public HttpController<LoginController>
{
public:
    static void registerUser(const HttpRequestPtr& req, Callback&& callback);
    static void login(const HttpRequestPtr& req, Callback&& callback);

    static void refresh(const HttpRequestPtr& req, Callback&& callback);
    static void logout(const HttpRequestPtr& req, Callback&& callback);

    static void oauth(const HttpRequestPtr& req, Callback&& callback, const std::string& code);

public:
    METHOD_LIST_BEGIN

        ADD_METHOD_TO(registerUser, "/register", Post);
        ADD_METHOD_TO(login, "/login", Get);
        ADD_METHOD_TO(refresh, "/refresh", Post);
        ADD_METHOD_TO(logout, "/logout", Post);

        ADD_METHOD_TO(oauth, "/oauth?code={code}", Get);

    METHOD_LIST_END

private:
    bool validateUser(const std::shared_ptr<Json::Value>& json);

private:
    static void saveRefreshToCookie(const std::string& token, const HttpResponsePtr& resp, int maxAge = 604800); // 7 days

    static std::string makeAccessToken(int id, const std::string& username);
    static std::string makeRefreshToken(int id, const std::string& username);

private:
    static constexpr auto oauth2Template =
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=profile";
};

}

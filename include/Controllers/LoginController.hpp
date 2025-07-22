#pragma once
#include <drogon/HttpController.h>

using namespace drogon;

using Callback = std::function<void(const HttpResponsePtr&)>;

namespace Controllers
{

class LoginController final : public HttpController<LoginController>
{
public:
    static void login(const HttpRequestPtr& req, Callback&& callback);
    static void logout(const HttpRequestPtr& req, Callback&& callback);

    static void oauth(
        const HttpRequestPtr& req, Callback&& callback,
        const std::string& code, const std::string& state
    );

public:
    METHOD_LIST_BEGIN

        ADD_METHOD_TO(login, "/login", Get);
        ADD_METHOD_TO(logout, "/logout", Post);

        ADD_METHOD_TO(oauth, "/oauth?code={code}&state={state}", Get);

    METHOD_LIST_END

private:
    static void requestUser(const HttpRequestPtr& req, const std::string& accessToken, Callback&& callback);

    static std::pair<std::string, std::string> processUser(const Json::Value& user);

private:
    static constexpr auto oauth2Template =
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&state={}&response_type=code&scope=profile";
};

}

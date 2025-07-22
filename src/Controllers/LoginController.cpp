#include "Controllers/LoginController.hpp"

#include "Utils/JwtUtils.hpp"

#include <drogon/HttpClient.h>
#include <drogon/orm/Mapper.h>

using namespace std::chrono_literals;

namespace Controllers
{

void LoginController::login(const HttpRequestPtr& req, Callback&& callback)
{
    const auto& config = app().getCustomConfig();
    const auto state = utils::secureRandomString(12);
    const auto link = std::format(
        oauth2Template,
        config["oauth2"]["client_id"].asString(),
        config["oauth2"]["redirect_uri"].asString(),
        state
    );

    req->getSession()->insert("oauth2_state", state);

    callback(HttpResponse::newRedirectionResponse(link));
}

void LoginController::logout(const HttpRequestPtr& req, Callback&& callback)
{
    const auto response = HttpResponse::newHttpResponse();

    // Removing cookie
    Utils::saveRefreshToCookie("", response, 0);

    // Clearing session
    req->getSession()->erase("jwtAccess");

    callback(response);
}

void LoginController::oauth(
    const HttpRequestPtr& req, Callback&& callback,
    const std::string& code, const std::string& state
)
{
    if(const auto sessionState = req->getSession()->get<std::string>("oauth2_state");
        state != sessionState || sessionState.empty())
    {
        callback(HttpResponse::newHttpResponse(k400BadRequest, CT_NONE));
        return;
    }

    req->getSession()->erase("oauth2_state");

    LOG_INFO << "OAuth2 code: " << code;

    const auto& config = app().getCustomConfig();

    static const auto client = HttpClient::newHttpClient("https://oauth2.googleapis.com/");

    const auto request = HttpRequest::newHttpFormPostRequest();
    request->setPath("/token");
    request->setParameter("code", code);
    request->setParameter("client_id", config["oauth2"]["client_id"].asString());
    request->setParameter("client_secret", config["oauth2"]["client_secret"].asString());
    request->setParameter("redirect_uri", config["oauth2"]["redirect_uri"].asString());
    request->setParameter("grant_type", "authorization_code");

    client->sendRequest(request,
        [callback = std::move(callback), req](const ReqResult reqRes, const HttpResponsePtr& resp)
        {
            const auto& json = *resp->getJsonObject();
            const auto access = json["access_token"].asString();

            LOG_INFO << "Access token: " << access;

            requestUser(req, access, static_cast<Callback>(std::move(callback)));
        });
}

void LoginController::requestUser(const HttpRequestPtr& req, const std::string& accessToken, Callback&& callback)
{
    static const auto client = HttpClient::newHttpClient("https://www.googleapis.com/");

    const auto request = HttpRequest::newHttpRequest();
    request->setPath("/oauth2/v2/userinfo");
    request->addHeader("Authorization", std::format("Bearer {}", accessToken));

    client->sendRequest(request,
        [callback = std::move(callback), req](const ReqResult reqRes, const HttpResponsePtr& resp)
        {
            if(const auto json = resp->getJsonObject(); json)
            {
                const auto [access, refresh] = processUser(*json);

                req->getSession()->insert("jwtAccess", access);

                Utils::saveRefreshToCookie(refresh, resp);

                callback(HttpResponse::newRedirectionResponse("/protected"));
            }
            else
                LOG_ERROR << "Failed to get user info";
        });
}

std::pair<std::string, std::string> LoginController::processUser(const Json::Value& user)
{
    LOG_INFO << "User info: " << user.toStyledString();

    const auto access = Utils::makeAccessToken(1, user["name"].asString());
    const auto refresh = Utils::makeRefreshToken(1, user["name"].asString());

    return { access, refresh };
}

}

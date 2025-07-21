#include <Controllers/LoginController.hpp>

#include <jwt-cpp/jwt.h>

#include <drogon/HttpClient.h>
#include <drogon/orm/Mapper.h>

using namespace std::chrono_literals;

namespace Controllers
{

void LoginController::registerUser(const HttpRequestPtr& req, Callback&& callback)
{
    if(const auto request = req->getJsonObject();
        !request || !request->isMember("username") || !request->isMember("password"))
    {
        const auto response = HttpResponse::newHttpResponse();
        response->setStatusCode(k400BadRequest);

        callback(response);
        return;
    }

    // Implement your own logic...
    // auto dbClient = app().getDbClient();
    // auto& mapper = orm::Mapper<models::User>(dbClient);

    login(req, std::move(callback));
}

void LoginController::login(const HttpRequestPtr& req, Callback&& callback)
{
    const auto& config = app().getCustomConfig();
    const auto link = std::format(
        oauth2Template,
        config["oauth2"]["client_id"].asString(),
        config["oauth2"]["redirect_uri"].asString()
    );

    callback(HttpResponse::newRedirectionResponse(link));
}

void LoginController::refresh(const HttpRequestPtr& req, Callback&& callback)
{
    static auto refreshSecret = app().getCustomConfig()["jwt"]["refresh_secret"].asString();

    const auto refreshToken = req->getCookie("refreshToken");

    if(refreshToken.empty())
    {
        const auto response = HttpResponse::newHttpResponse();
        response->setStatusCode(k401Unauthorized);

        callback(response);
        return;
    }

    try
    {
        const auto decoded = jwt::decode(refreshToken);
        const auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256(refreshSecret))
            .with_issuer("auth0");

        verifier.verify(decoded);

        const auto accessToken =
            makeAccessToken(
                decoded.get_payload_claim("user_id").as_integer(),
                decoded.get_payload_claim("username").as_string()
            );

        Json::Value json;
        json["token"] = accessToken;

        const auto response = HttpResponse::newHttpJsonResponse(json);

        callback(response);
    }
    catch(...)
    {
        const auto response = HttpResponse::newHttpResponse();
        response->setStatusCode(k401Unauthorized);

        callback(response);
    }
}

void LoginController::logout(const HttpRequestPtr& req, Callback&& callback)
{
    const auto response = HttpResponse::newHttpResponse();

    // Removing cookie
    saveRefreshToCookie("", response, 0);

    callback(response);
}

void LoginController::oauth(const HttpRequestPtr& req, Callback&& callback, const std::string& code)
{
    LOG_INFO << "OAuth2 code: " << code;

    const auto& config = app().getCustomConfig();

    static const auto client = HttpClient::newHttpClient("https://oauth2.googleapis.com/token");

    const auto request = HttpRequest::newHttpFormPostRequest();
    request->setPath("/token");
    request->setParameter("code", code);
    request->setParameter("client_id", config["oauth2"]["client_id"].asString());
    request->setParameter("client_secret", config["oauth2"]["client_secret"].asString());
    request->setParameter("redirect_uri", config["oauth2"]["redirect_uri"].asString());
    request->setParameter("grant_type", "authorization_code");

    client->sendRequest(request,
        [callback](ReqResult reqRes, const HttpResponsePtr& resp)
        {
            const auto& json = *resp->getJsonObject();
            const auto access = json["access_token"].asString();

            LOG_INFO << "Access token: " << access;

            callback(HttpResponse::newRedirectionResponse("/success?msg=Done"));
        });
}

void LoginController::saveRefreshToCookie(const std::string& token, const HttpResponsePtr& resp, const int maxAge)
{
    Cookie cookie("refreshToken", token);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setSameSite(Cookie::SameSite::kStrict);
    cookie.setPath("/refresh");
    cookie.setMaxAge(maxAge);

    resp->addCookie(cookie);
}

bool LoginController::validateUser(const std::shared_ptr<Json::Value>& json)
{
    // Implement your own validation logic
    return true;
}

std::string LoginController::makeAccessToken(const int id, const std::string& username)
{
    static auto accessSecret = app().getCustomConfig()["jwt"]["access_secret"].asString();

    auto token = jwt::create()
        .set_issuer("auth0")
        .set_type("JWS")
        .set_expires_in(3600s) // 1 hour
        .set_payload_claim(
            "user_id",
            jwt::claim(std::to_string(id))
        )
        .set_payload_claim(
            "username",
            jwt::claim(username)
        )
        .sign(jwt::algorithm::hs256(accessSecret)); // Change the secret to something *really* secret (in config)

    return token;
}

std::string LoginController::makeRefreshToken(const int id, const std::string& username)
{
    static auto refreshSecret = app().getCustomConfig()["jwt"]["refresh_secret"].asString();

    auto token = jwt::create()
        .set_issuer("auth0")
        .set_type("JWS")
        .set_expires_in(604800s) // 7 days
        .set_payload_claim(
            "user_id",
            jwt::claim(std::to_string(id))
        )
        .set_payload_claim(
            "username",
            jwt::claim(username)
        )
        .sign(jwt::algorithm::hs256(refreshSecret));

    return token;
}

}

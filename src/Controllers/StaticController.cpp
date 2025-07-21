#include <Controllers/StaticController.hpp>

namespace Controllers
{

void StaticController::swaggerPage(const HttpRequestPtr& req, Callback&& callback)
{
    callback(HttpResponse::newRedirectionResponse("swagger/index.html"));
}

void StaticController::swaggerFile(const HttpRequestPtr& req, Callback&& callback)
{
    callback(HttpResponse::newFileResponse("../static/swagger.json"));
}

void StaticController::success(const HttpRequestPtr& req, Callback&& callback, const std::string& msg)
{
    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(std::format("<html><head></head><body>Success:</br>{}</body></html>", msg));

    callback(resp);
}

}

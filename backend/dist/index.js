"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const app_config_1 = require("./config/app.config");
const database_config_1 = __importDefault(require("./config/database.config"));
const errorHandler_middleware_1 = require("./middlewares/errorHandler.middleware");
const http_config_1 = require("./config/http.config");
const asyncHandler_middleware_1 = require("./middlewares/asyncHandler.middleware");
const appError_1 = require("./utils/appError");
const error_code_enum_1 = require("./enums/error-code.enum");
require("./config/passport.config");
const passport_1 = __importDefault(require("passport"));
const auth_route_1 = __importDefault(require("./routes/auth.route"));
const user_route_1 = __importDefault(require("./routes/user.route"));
const isAuthenticated_middleware_1 = __importDefault(require("./middlewares/isAuthenticated.middleware"));
const workspace_route_1 = __importDefault(require("./routes/workspace.route"));
const member_route_1 = __importDefault(require("./routes/member.route"));
const project_route_1 = __importDefault(require("./routes/project.route"));
const task_route_1 = __importDefault(require("./routes/task.route"));
const app = (0, express_1.default)();
const BASE_PATH = app_config_1.config.BASE_PATH;
app.use(express_1.default.json());
app.use(express_1.default.urlencoded({ extended: true }));
app.use((0, cookie_session_1.default)({
    name: "session",
    keys: [app_config_1.config.SESSION_SECRET],
    maxAge: 24 * 60 * 60 * 1000,
    secure: app_config_1.config.NODE_ENV === "production",
    httpOnly: true,
    sameSite: app_config_1.config.NODE_ENV === "production" ? "none" : "lax",
}));
app.use(passport_1.default.initialize());
app.use(passport_1.default.session());
app.use((0, cors_1.default)({
    origin: app_config_1.config.FRONTEND_ORIGIN,
    credentials: true,
}));
app.get(`/`, (0, asyncHandler_middleware_1.asyncHandler)(async (req, res, next) => {
    // In production we should not throw on the root path because
    // platforms (like Render) poll the root URL for health checks.
    // Return a simple health/status response. If you need to surface
    // errors for debugging, keep them behind a development flag.
    if (app_config_1.config.NODE_ENV !== "production") {
        // In development, allow a test error to be thrown when explicitly requested
        const { testError } = req.query;
        if (testError === "1") {
            throw new appError_1.BadRequestException("This is a bad request", error_code_enum_1.ErrorCodeEnum.AUTH_INVALID_TOKEN);
        }
    }
    return res.status(http_config_1.HTTPSTATUS.OK).json({
        status: "ok",
        env: app_config_1.config.NODE_ENV,
        message: "Service is running",
    });
}));
app.use(`${BASE_PATH}/auth`, auth_route_1.default);
app.use(`${BASE_PATH}/user`, isAuthenticated_middleware_1.default, user_route_1.default);
app.use(`${BASE_PATH}/workspace`, isAuthenticated_middleware_1.default, workspace_route_1.default);
app.use(`${BASE_PATH}/member`, isAuthenticated_middleware_1.default, member_route_1.default);
app.use(`${BASE_PATH}/project`, isAuthenticated_middleware_1.default, project_route_1.default);
app.use(`${BASE_PATH}/task`, isAuthenticated_middleware_1.default, task_route_1.default);
app.use(errorHandler_middleware_1.errorHandler);
app.listen(app_config_1.config.PORT, async () => {
    console.log(`Server listening on port ${app_config_1.config.PORT} in ${app_config_1.config.NODE_ENV}`);
    await (0, database_config_1.default)();
});

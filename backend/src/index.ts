import dotenv from 'dotenv';
dotenv.config();
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import session from "cookie-session";
import { config } from "./config/app.config";
import connectDatabase from "./config/database.config";
import { errorHandler } from "./middlewares/errorHandler.middleware";
import { HTTPSTATUS } from "./config/http.config";
import { asyncHandler } from "./middlewares/asyncHandler.middleware";
import { BadRequestException } from "./utils/appError";
import { ErrorCodeEnum } from "./enums/error-code.enum";

import "./config/passport.config";
import passport from "passport";
import authRoutes from "./routes/auth.route";
import userRoutes from "./routes/user.route";
import isAuthenticated from "./middlewares/isAuthenticated.middleware";
import workspaceRoutes from "./routes/workspace.route";
import memberRoutes from "./routes/member.route";
import projectRoutes from "./routes/project.route";
import taskRoutes from "./routes/task.route";

const app = express();
const BASE_PATH = config.BASE_PATH;

// If app is behind a proxy (Render, Heroku, etc.) we must trust it so express
// recognizes the original scheme/proto. This is required for secure cookies.
app.set('trust proxy', 1);

// Important: apply CORS before session/cookie middleware so that cross-site
// responses (including Set-Cookie) include the Access-Control-Allow-* headers.
app.use(
  cors({
    origin: config.FRONTEND_ORIGIN, // exact origin, no wildcard
    credentials: true,
  })
);

// Body parsers after CORS
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session / cookie middleware after CORS and after trust proxy is set
app.use(
  session({
    name: "session",
    keys: [config.SESSION_SECRET],
    maxAge: Number(config.SESSION_EXPIRES_IN) || 24 * 60 * 60 * 1000,
    secure: true,         // requires HTTPS; Render provides HTTPS
    httpOnly: true,
    sameSite: 'none',     // required for cross-site cookie use
  })
);

app.use(passport.initialize());
app.use(passport.session());


app.get(
  `/`,
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    // In production we should not throw on the root path because
    // platforms (like Render) poll the root URL for health checks.
    // Return a simple health/status response. If you need to surface
    // errors for debugging, keep them behind a development flag.
    if (config.NODE_ENV !== "production") {
      // In development, allow a test error to be thrown when explicitly requested
      const { testError } = req.query;
      if (testError === "1") {
        throw new BadRequestException(
          "This is a bad request",
          ErrorCodeEnum.AUTH_INVALID_TOKEN
        );
      }
    }

    return res.status(HTTPSTATUS.OK).json({
      status: "ok",
      env: config.NODE_ENV,
      message: "Service is running",
    });
  })
);

app.use(`${BASE_PATH}/auth`, authRoutes);
app.use(`${BASE_PATH}/user`, isAuthenticated, userRoutes);
app.use(`${BASE_PATH}/workspace`, isAuthenticated, workspaceRoutes);
app.use(`${BASE_PATH}/member`, isAuthenticated, memberRoutes);
app.use(`${BASE_PATH}/project`, isAuthenticated, projectRoutes);
app.use(`${BASE_PATH}/task`, isAuthenticated, taskRoutes);

app.use(errorHandler);

app.listen(config.PORT, async () => {
  console.log(`Server listening on port ${config.PORT} in ${config.NODE_ENV}`);
  await connectDatabase();
});

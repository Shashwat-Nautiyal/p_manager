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

// CORS must be set before session to allow credentials
app.use(
  cors({
    origin: config.FRONTEND_ORIGIN,
    credentials: true,
  })
);

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "session",
    keys: [config.SESSION_SECRET],
    maxAge: 24 * 60 * 60 * 1000,
    secure: config.NODE_ENV === "production",
    httpOnly: true,
    sameSite: config.NODE_ENV === "production" ? "none" : "lax",
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Middleware to ensure SameSite=None is set correctly in production
if (config.NODE_ENV === "production") {
  app.use((req, res, next) => {
    const originalSetHeader = res.setHeader.bind(res);
    res.setHeader = function (name: string, value: any) {
      if (name.toLowerCase() === 'set-cookie') {
        const cookies = Array.isArray(value) ? value : [value];
        const updatedCookies = cookies.map((cookie: string) => {
          // If the cookie doesn't already have SameSite=None, add it
          if (cookie.includes('session=') && !cookie.includes('SameSite=None')) {
            // Remove any existing SameSite attribute
            let updatedCookie = cookie.replace(/;\s*SameSite=\w+/gi, '');
            // Add SameSite=None
            if (!updatedCookie.includes('SameSite')) {
              updatedCookie += '; SameSite=None';
            }
            // Ensure Secure is present
            if (!updatedCookie.includes('Secure')) {
              updatedCookie += '; Secure';
            }
            return updatedCookie;
          }
          return cookie;
        });
        return originalSetHeader('Set-Cookie', updatedCookies);
      }
      return originalSetHeader(name, value);
    };
    next();
  });
}

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

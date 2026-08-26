import "dotenv/config";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import cors from "cors";
import {
  createHmac,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { prisma } from "./prisma.js";

const app = express();
const port = Number(process.env.PORT ?? 3001);
const frontendOrigins = new Set(
  (process.env.FRONTEND_ORIGIN ?? "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
);
const ADMIN_COOKIE_NAME = "taviv_admin_session";
const ADMIN_SESSION_TTL_SECONDS = 60 * 60 * 8;

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || frontendOrigins.has(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error("Origin is not allowed by CORS"));
    },
    credentials: true,
  }),
);
app.use(express.json());

class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type CreateOrderItemInput = {
  slug: string;
  kilograms: number;
  quantity?: number;
};

type CreateOrderInput = {
  customerName: string;
  phoneNumber: string;
  deliveryLocation: string;
  orderNote?: string;
  email?: string;
  items: CreateOrderItemInput[];
  deliveryFee?: number;
  paymentMethod?: "CASH" | "MPESA";
};

type AdminSession = {
  username: string;
  expiresAt: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function requireNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ApiError(400, `${fieldName} is required`);
  }

  return value.trim();
}

function optionalString(
  value: unknown,
  fieldName: string,
): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value !== "string") {
    throw new ApiError(400, `${fieldName} must be a string`);
  }

  const trimmedValue = value.trim();
  return trimmedValue.length === 0 ? undefined : trimmedValue;
}

function requirePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new ApiError(400, `${fieldName} must be a positive number`);
  }

  return value;
}

function requirePositiveInteger(value: unknown, fieldName: string): number {
  if (!Number.isInteger(value) || Number(value) <= 0) {
    throw new ApiError(400, `${fieldName} must be a positive integer`);
  }

  return Number(value);
}

function requireNonNegativeNumber(value: unknown, fieldName: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new ApiError(400, `${fieldName} must be zero or a positive number`);
  }

  return value;
}

function parseCreateOrderInput(body: unknown): CreateOrderInput {
  if (!isRecord(body)) {
    throw new ApiError(400, "Request body must be a JSON object");
  }

  if (!Array.isArray(body.items) || body.items.length === 0) {
    throw new ApiError(400, "At least one order item is required");
  }

  const items = body.items.map((rawItem, index) => {
    if (!isRecord(rawItem)) {
      throw new ApiError(400, `items[${index}] must be an object`);
    }

    const slug = requireNonEmptyString(rawItem.slug, `items[${index}].slug`);
    const kilograms = requirePositiveNumber(
      rawItem.kilograms,
      `items[${index}].kilograms`,
    );
    const quantity =
      rawItem.quantity === undefined
        ? 1
        : requirePositiveInteger(rawItem.quantity, `items[${index}].quantity`);

    return { slug, kilograms, quantity };
  });

  const deliveryFee =
    body.deliveryFee === undefined
      ? 0
      : body.deliveryFee === null
        ? 0
        : requireNonNegativeNumber(body.deliveryFee, "deliveryFee");

  const paymentMethod = body.paymentMethod ?? "CASH";
  if (paymentMethod !== "CASH" && paymentMethod !== "MPESA") {
    throw new ApiError(400, "paymentMethod must be CASH or MPESA");
  }

  return {
    customerName: requireNonEmptyString(body.customerName, "customerName"),
    phoneNumber: requireNonEmptyString(body.phoneNumber, "phoneNumber"),
    deliveryLocation: requireNonEmptyString(
      body.deliveryLocation,
      "deliveryLocation",
    ),
    orderNote: optionalString(body.orderNote, "orderNote"),
    email: optionalString(body.email, "email"),
    items,
    deliveryFee,
    paymentMethod,
  };
}

function createOrderNumber(): string {
  return `TAV-${Date.now().toString(36).toUpperCase()}-${randomUUID()
    .slice(0, 8)
    .toUpperCase()}`;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function getAdminConfig() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  const sessionSecret = process.env.ADMIN_SESSION_SECRET;

  if (!username || !password || !sessionSecret) {
    throw new ApiError(
      500,
      "Admin authentication is not configured on the server",
    );
  }

  return { username, password, sessionSecret };
}

function createAdminSession(username: string, sessionSecret: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      username,
      expiresAt: Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000,
    }),
  ).toString("base64url");
  const signature = createHmac("sha256", sessionSecret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function readCookies(request: Request): Record<string, string> {
  const cookieHeader = request.headers.cookie;
  if (!cookieHeader) {
    return {};
  }

  return Object.fromEntries(
    cookieHeader.split(";").flatMap((part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex < 0) {
        return [];
      }

      const name = part.slice(0, separatorIndex).trim();
      const value = part.slice(separatorIndex + 1).trim();
      return [[name, decodeURIComponent(value)]];
    }),
  );
}

function readAdminSession(request: Request): AdminSession | null {
  const sessionSecret = process.env.ADMIN_SESSION_SECRET;
  if (!sessionSecret) {
    return null;
  }

  const token = readCookies(request)[ADMIN_COOKIE_NAME];
  if (!token) {
    return null;
  }

  const [payload, signature] = token.split(".");
  if (!payload || !signature) {
    return null;
  }

  const expectedSignature = createHmac("sha256", sessionSecret)
    .update(payload)
    .digest("base64url");

  if (!constantTimeEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as AdminSession;

    if (
      typeof session.username !== "string" ||
      typeof session.expiresAt !== "number" ||
      session.expiresAt <= Date.now()
    ) {
      return null;
    }

    return session;
  } catch {
    return null;
  }
}

function requestUsesHttps(request: Request): boolean {
  const forwardedProto = request.headers["x-forwarded-proto"];
  const protocol = Array.isArray(forwardedProto)
    ? forwardedProto[0]
    : forwardedProto;

  return request.protocol === "https" || protocol === "https";
}

function setAdminCookie(
  request: Request,
  response: Response,
  token: string,
): void {
  const secure = requestUsesHttps(request) ? "; Secure" : "";
  const sameSite = secure ? "None" : "Lax";

  response.setHeader(
    "Set-Cookie",
    `${ADMIN_COOKIE_NAME}=${encodeURIComponent(token)}; Max-Age=${ADMIN_SESSION_TTL_SECONDS}; Path=/; HttpOnly; SameSite=${sameSite}${secure}`,
  );
}

function clearAdminCookie(request: Request, response: Response): void {
  const secure = requestUsesHttps(request) ? "; Secure" : "";
  const sameSite = secure ? "None" : "Lax";

  response.setHeader(
    "Set-Cookie",
    `${ADMIN_COOKIE_NAME}=; Max-Age=0; Path=/; HttpOnly; SameSite=${sameSite}${secure}`,
  );
}

function requireAdmin(
  request: Request,
  response: Response,
  next: NextFunction,
): void {
  const session = readAdminSession(request);
  if (!session) {
    response.status(401).json({ error: "Admin authentication required" });
    return;
  }

  next();
}

app.get("/api/health", async (_request, response, next) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    response.json({ ok: true, database: "connected" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/inventory", async (_request, response, next) => {
  try {
    const inventory = await prisma.porkCut.findMany({
      where: { isActive: true },
      orderBy: [{ isFeatured: "desc" }, { name: "asc" }],
      select: {
        id: true,
        name: true,
        slug: true,
        availableKg: true,
        isActive: true,
        isFeatured: true,
        pricePerKg: true,
        image: true,
      },
    });

    response.json(inventory);
  } catch (error) {
    next(error);
  }
});

app.post("/api/orders", async (request, response, next) => {
  try {
    const input = parseCreateOrderInput(request.body);

    const order = await prisma.$transaction(async (transaction) => {
      const requestedSlugs = [...new Set(input.items.map((item) => item.slug))];
      const porkCuts = await transaction.porkCut.findMany({
        where: {
          slug: { in: requestedSlugs },
          isActive: true,
        },
      });

      const porkCutsBySlug = new Map(
        porkCuts.map((porkCut) => [porkCut.slug, porkCut]),
      );

      const mergedItems = new Map<
        string,
        { kilograms: number; quantity: number }
      >();

      for (const item of input.items) {
        const porkCut = porkCutsBySlug.get(item.slug);
        if (!porkCut) {
          throw new ApiError(404, `Pork cut not found: ${item.slug}`);
        }

        const previous = mergedItems.get(item.slug);
        mergedItems.set(item.slug, {
          kilograms: (previous?.kilograms ?? 0) + item.kilograms,
          quantity: (previous?.quantity ?? 0) + (item.quantity ?? 1),
        });
      }

      const orderLines = [...mergedItems.entries()].map(([slug, item]) => {
        const porkCut = porkCutsBySlug.get(slug)!;
        return { porkCut, ...item };
      });

      const subtotal = orderLines.reduce(
        (sum, line) => sum + line.kilograms * line.porkCut.pricePerKg,
        0,
      );
      const total = subtotal + (input.deliveryFee ?? 0);

      let customer = await transaction.customer.findFirst({
        where: { phone: input.phoneNumber },
      });

      if (customer) {
        customer = await transaction.customer.update({
          where: { id: customer.id },
          data: {
            name: input.customerName,
            address: input.deliveryLocation,
            ...(input.email === undefined ? {} : { email: input.email }),
          },
        });
      } else {
        customer = await transaction.customer.create({
          data: {
            name: input.customerName,
            phone: input.phoneNumber,
            email: input.email,
            address: input.deliveryLocation,
          },
        });
      }

      const createdOrder = await transaction.order.create({
        data: {
          orderNumber: createOrderNumber(),
          customerId: customer.id,
          subtotal,
          deliveryFee: input.deliveryFee ?? 0,
          total,
          customerNote: input.orderNote,
          deliveryAddress: input.deliveryLocation,
          deliveryPhone: input.phoneNumber,
          items: {
            create: orderLines.map((line) => ({
              porkCutId: line.porkCut.id,
              quantity: line.quantity,
              kilograms: line.kilograms,
              pricePerKg: line.porkCut.pricePerKg,
              costPerKg: line.porkCut.costPerKg,
              subtotal: line.kilograms * line.porkCut.pricePerKg,
            })),
          },
          payment: {
            create: {
              method: input.paymentMethod ?? "CASH",
              amount: total,
            },
          },
        },
        select: {
          orderNumber: true,
          status: true,
          subtotal: true,
          deliveryFee: true,
          total: true,
        },
      });

      for (const line of orderLines) {
        const stockUpdate = await transaction.porkCut.updateMany({
          where: {
            id: line.porkCut.id,
            isActive: true,
            availableKg: { gte: line.kilograms },
          },
          data: {
            availableKg: { decrement: line.kilograms },
          },
        });

        if (stockUpdate.count !== 1) {
          throw new ApiError(
            409,
            `Not enough stock for ${line.porkCut.name}`,
          );
        }
      }

      return createdOrder;
    });

    response.status(201).json(order);
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/login", async (request, response, next) => {
  try {
    if (!isRecord(request.body)) {
      throw new ApiError(400, "Request body must be a JSON object");
    }

    const username = requireNonEmptyString(
      request.body.username,
      "username",
    );
    const password = requireNonEmptyString(
      request.body.password,
      "password",
    );
    const config = getAdminConfig();

    if (
      !constantTimeEqual(username, config.username) ||
      !constantTimeEqual(password, config.password)
    ) {
      throw new ApiError(401, "Invalid admin credentials");
    }

    setAdminCookie(
      request,
      response,
      createAdminSession(config.username, config.sessionSecret),
    );
    response.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/logout", (request, response) => {
  clearAdminCookie(request, response);
  response.json({ ok: true });
});

app.get("/api/admin/me", (request, response) => {
  const session = readAdminSession(request);
  if (!session) {
    response.status(401).json({ error: "Admin authentication required" });
    return;
  }

  response.json({ authenticated: true, username: session.username });
});

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  async (_request, response, next) => {
    try {
      const activeOrdersWhere = {
        status: { not: "CANCELLED" as const },
      };

      const [
        totalOrders,
        revenueAggregate,
        pendingOrders,
        customers,
        completedOrderItems,
        orders,
      ] = await Promise.all([
        prisma.order.count({ where: activeOrdersWhere }),
        prisma.order.aggregate({
          where: activeOrdersWhere,
          _sum: { total: true },
        }),
        prisma.order.count({ where: { status: "PENDING" } }),
        prisma.customer.count(),
        prisma.orderItem.findMany({
          where: { order: { status: "COMPLETED" } },
          select: {
            kilograms: true,
            pricePerKg: true,
            costPerKg: true,
          },
        }),
        prisma.order.findMany({
          where: activeOrdersWhere,
          orderBy: { createdAt: "desc" },
          take: 20,
          select: {
            orderNumber: true,
            status: true,
            total: true,
            createdAt: true,
            customer: {
              select: {
                name: true,
                phone: true,
              },
            },
          },
        }),
      ]);

      const totalProfit = completedOrderItems.reduce(
        (sum, item) =>
          sum + item.kilograms * (item.pricePerKg - item.costPerKg),
        0,
      );

      response.json({
        stats: {
          totalOrders,
          revenue: revenueAggregate._sum.total ?? 0,
          pendingOrders,
          customers,
          totalProfit,
        },
        orders,
      });
    } catch (error) {
      next(error);
    }
  },
);

const orderStatuses = [
  "PENDING",
  "CONFIRMED",
  "PROCESSING",
  "READY",
  "OUT_FOR_DELIVERY",
  "COMPLETED",
  "CANCELLED",
] as const;

type OrderStatus = (typeof orderStatuses)[number];

function isOrderStatus(value: unknown): value is OrderStatus {
  return (
    typeof value === "string" &&
    (orderStatuses as readonly string[]).includes(value)
  );
}

app.get(
  "/api/admin/orders",
  requireAdmin,
  async (_request, response, next) => {
    try {
      const orders = await prisma.order.findMany({
        orderBy: { createdAt: "desc" },
        take: 100,
        select: {
          id: true,
          orderNumber: true,
          status: true,
          subtotal: true,
          deliveryFee: true,
          total: true,
          customerNote: true,
          deliveryAddress: true,
          deliveryPhone: true,
          createdAt: true,
          customer: {
            select: {
              name: true,
              phone: true,
              email: true,
            },
          },
          items: {
            select: {
              quantity: true,
              kilograms: true,
              pricePerKg: true,
              subtotal: true,
              porkCut: {
                select: {
                  name: true,
                  slug: true,
                },
              },
            },
          },
          payment: {
            select: {
              method: true,
              status: true,
              amount: true,
              mpesaReceiptNumber: true,
            },
          },
        },
      });

      response.json(orders);
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/admin/orders/:orderNumber/status",
  requireAdmin,
  async (request, response, next) => {
    try {
      if (!isRecord(request.body) || !isOrderStatus(request.body.status)) {
        throw new ApiError(400, "A valid order status is required");
      }

      const orderNumber = Array.isArray(request.params.orderNumber)
        ? request.params.orderNumber[0]
        : request.params.orderNumber;

      if (!orderNumber) {
        throw new ApiError(400, "Order number is required");
      }

      const order = await prisma.order.update({
        where: { orderNumber },
        data: { status: request.body.status },
        select: {
          orderNumber: true,
          status: true,
          updatedAt: true,
        },
      });

      response.json(order);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/inventory",
  requireAdmin,
  async (_request, response, next) => {
    try {
      const inventory = await prisma.porkCut.findMany({
        orderBy: [{ isFeatured: "desc" }, { name: "asc" }],
        select: {
          id: true,
          name: true,
          slug: true,
          availableKg: true,
          isActive: true,
          isFeatured: true,
          pricePerKg: true,
        },
      });

      response.json(inventory);
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/admin/inventory/:slug",
  requireAdmin,
  async (request, response, next) => {
    try {
      if (!isRecord(request.body)) {
        throw new ApiError(400, "Request body must be a JSON object");
      }

      const slug = Array.isArray(request.params.slug)
        ? request.params.slug[0]
        : request.params.slug;

      if (!slug) {
        throw new ApiError(400, "Pork-cut slug is required");
      }

      const availableKg = requireNonNegativeNumber(
        request.body.availableKg,
        "availableKg",
      );
      const isActive = request.body.isActive;
      if (isActive !== undefined && typeof isActive !== "boolean") {
        throw new ApiError(400, "isActive must be a boolean");
      }

      const porkCut = await prisma.porkCut.update({
        where: { slug },
        data: {
          availableKg,
          ...(isActive === undefined ? {} : { isActive }),
        },
        select: {
          id: true,
          name: true,
          slug: true,
          availableKg: true,
          isActive: true,
          pricePerKg: true,
        },
      });

      response.json(porkCut);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/customers",
  requireAdmin,
  async (_request, response, next) => {
    try {
      const customers = await prisma.customer.findMany({
        orderBy: { createdAt: "desc" },
        take: 100,
        select: {
          id: true,
          name: true,
          phone: true,
          email: true,
          address: true,
          createdAt: true,
          _count: {
            select: {
              orders: true,
            },
          },
        },
      });

      response.json(customers);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/reports",
  requireAdmin,
  async (_request, response, next) => {
    try {
      const [completedOrders, completedItems] = await Promise.all([
        prisma.order.findMany({
          where: { status: "COMPLETED" },
          select: {
            total: true,
            createdAt: true,
          },
          orderBy: { createdAt: "asc" },
        }),
        prisma.orderItem.findMany({
          where: { order: { status: "COMPLETED" } },
          select: {
            kilograms: true,
            pricePerKg: true,
            costPerKg: true,
            subtotal: true,
            porkCut: {
              select: {
                name: true,
                slug: true,
              },
            },
          },
        }),
      ]);

      const revenue = completedOrders.reduce(
        (sum, order) => sum + order.total,
        0,
      );
      const cost = completedItems.reduce(
        (sum, item) => sum + item.kilograms * item.costPerKg,
        0,
      );
      const profit = revenue - cost;

      const cutTotals = new Map<
        string,
        { name: string; slug: string; kilograms: number; revenue: number }
      >();
      for (const item of completedItems) {
        const previous = cutTotals.get(item.porkCut.slug);
        cutTotals.set(item.porkCut.slug, {
          name: item.porkCut.name,
          slug: item.porkCut.slug,
          kilograms: (previous?.kilograms ?? 0) + item.kilograms,
          revenue: (previous?.revenue ?? 0) + item.subtotal,
        });
      }

      const dailyTotals = new Map<string, number>();
      for (const order of completedOrders) {
        const day = order.createdAt.toISOString().slice(0, 10);
        dailyTotals.set(day, (dailyTotals.get(day) ?? 0) + order.total);
      }

      response.json({
        summary: {
          completedOrders: completedOrders.length,
          revenue,
          cost,
          profit,
        },
        topCuts: [...cutTotals.values()].sort(
          (left, right) => right.revenue - left.revenue,
        ),
        dailyRevenue: [...dailyTotals.entries()].map(
          ([date, amount]) => ({ date, amount }),
        ),
      });
    } catch (error) {
      next(error);
    }
  },
);

app.use(
  (
    error: unknown,
    _request: Request,
    response: Response,
    _next: NextFunction,
  ) => {
    if (error instanceof ApiError) {
      response.status(error.statusCode).json({
        error: error.message,
      });
      return;
    }

    console.error("[Server] Unexpected error:", error);
    response.status(500).json({
      error: "Internal server error",
    });
  },
);

if (
  process.env.VERCEL !== "1" &&
  process.env.NODE_ENV !== "test"
) {
  const host = process.env.HOST ?? "0.0.0.0";

  app.listen(port, host, () => {
    console.log(`Taviv API listening on ${host}:${port}`);
  });
}

export default app;

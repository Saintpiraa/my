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

type DarajaConfig = {
  baseUrl: string;
  consumerKey: string;
  consumerSecret: string;
  shortcode: string;
  passkey: string;
  transactionType: "CustomerPayBillOnline" | "CustomerBuyGoodsOnline";
  callbackUrl: string;
};

type DarajaStkResponse = {
  MerchantRequestID?: string;
  CheckoutRequestID?: string;
  ResponseCode?: string | number;
  ResponseDescription?: string;
  CustomerMessage?: string;
};

type DarajaCallback = {
  Body?: {
    stkCallback?: Record<string, unknown>;
  };
};

function getDarajaConfig(): DarajaConfig {
  const environment = process.env.DARAJA_ENV ?? "sandbox";
  if (environment !== "sandbox" && environment !== "production") {
    throw new ApiError(
      500,
      "DARAJA_ENV must be sandbox or production",
    );
  }

  const consumerKey = process.env.DARAJA_CONSUMER_KEY;
  const consumerSecret = process.env.DARAJA_CONSUMER_SECRET;
  const shortcode = process.env.DARAJA_SHORTCODE;
  const passkey = process.env.DARAJA_PASSKEY;
  const callbackUrl = process.env.DARAJA_CALLBACK_URL;
  const transactionType =
    process.env.DARAJA_TRANSACTION_TYPE ?? "CustomerPayBillOnline";

  if (
    !consumerKey ||
    !consumerSecret ||
    !shortcode ||
    !passkey ||
    !callbackUrl
  ) {
    throw new ApiError(
      503,
      "M-Pesa Sandbox payment integration is not configured on the server",
    );
  }

  if (
    transactionType !== "CustomerPayBillOnline" &&
    transactionType !== "CustomerBuyGoodsOnline"
  ) {
    throw new ApiError(
      500,
      "DARAJA_TRANSACTION_TYPE must be CustomerPayBillOnline or CustomerBuyGoodsOnline",
    );
  }

  return {
    baseUrl:
      process.env.DARAJA_BASE_URL ??
      (environment === "production"
        ? "https://api.safaricom.co.ke"
        : "https://sandbox.safaricom.co.ke"),
    consumerKey,
    consumerSecret,
    shortcode,
    passkey,
    transactionType,
    callbackUrl,
  };
}

function normalizeKenyanPhone(value: string): string {
  const digits = value.replace(/[^0-9]/g, "");
  const normalized =
    digits.length === 10 && digits.startsWith("0")
      ? `254${digits.slice(1)}`
      : digits;

  if (!/^254[17][0-9]{8}$/.test(normalized)) {
    throw new ApiError(
      400,
      "phoneNumber must be a Kenyan mobile number, for example 0712345678",
    );
  }

  return normalized;
}

function darajaTimestamp(date = new Date()): string {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Africa/Nairobi",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);

  const valueFor = (type: string) =>
    parts.find((part) => part.type === type)?.value ?? "";

  return [
    valueFor("year"),
    valueFor("month"),
    valueFor("day"),
    valueFor("hour"),
    valueFor("minute"),
    valueFor("second"),
  ].join("");
}

async function getDarajaAccessToken(config: DarajaConfig): Promise<string> {
  const basicCredentials = Buffer.from(
    `${config.consumerKey}:${config.consumerSecret}`,
  ).toString("base64");
  const tokenResponse = await fetch(
    `${config.baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${basicCredentials}`,
        Accept: "application/json",
      },
    },
  );
  const tokenBody = (await tokenResponse.json().catch(() => ({}))) as {
    access_token?: string;
  };

  if (!tokenResponse.ok || !tokenBody.access_token) {
    throw new ApiError(502, "Daraja authorization failed");
  }

  return tokenBody.access_token;
}

async function initiateDarajaStkPush(input: {
  config: DarajaConfig;
  phoneNumber: string;
  amount: number;
  orderNumber: string;
}): Promise<{
  checkoutRequestId: string;
  merchantRequestId?: string;
  customerMessage: string;
  phoneNumber: string;
}> {
  const phoneNumber = normalizeKenyanPhone(input.phoneNumber);
  const amount = Math.max(1, Math.round(input.amount));
  const timestamp = darajaTimestamp();
  const password = Buffer.from(
    `${input.config.shortcode}${input.config.passkey}${timestamp}`,
  ).toString("base64");
  const accountReference = input.orderNumber
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, 12);
  const accessToken = await getDarajaAccessToken(input.config);

  const stkResponse = await fetch(
    `${input.config.baseUrl}/mpesa/stkpush/v1/processrequest`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        BusinessShortCode: input.config.shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: input.config.transactionType,
        Amount: amount,
        PartyA: phoneNumber,
        PartyB: input.config.shortcode,
        PhoneNumber: phoneNumber,
        CallBackURL: input.config.callbackUrl,
        AccountReference: accountReference,
        TransactionDesc: "Taviv order",
      }),
    },
  );
  const responseBody = (await stkResponse.json().catch(() => ({}))) as DarajaStkResponse;

  if (
    !stkResponse.ok ||
    String(responseBody.ResponseCode) !== "0" ||
    !responseBody.CheckoutRequestID
  ) {
    throw new ApiError(502, "Daraja did not accept the payment request");
  }

  return {
    checkoutRequestId: responseBody.CheckoutRequestID,
    merchantRequestId: responseBody.MerchantRequestID,
    customerMessage:
      responseBody.CustomerMessage ??
      "Payment request sent. Check your phone and enter your M-Pesa PIN.",
    phoneNumber,
  };
}

function callbackMetadataValue(
  callback: Record<string, unknown>,
  name: string,
): string | number | undefined {
  const metadata = callback.CallbackMetadata;
  if (!isRecord(metadata) || !Array.isArray(metadata.Item)) {
    return undefined;
  }

  const matchingItem = metadata.Item.find(
    (item) => isRecord(item) && item.Name === name,
  );

  if (!isRecord(matchingItem)) {
    return undefined;
  }

  return typeof matchingItem.Value === "string" ||
    typeof matchingItem.Value === "number"
    ? matchingItem.Value
    : undefined;
}

async function failPaymentAndReleaseStock(orderId: string): Promise<void> {
  await prisma.$transaction(async (transaction) => {
    const order = await transaction.order.findUnique({
      where: { id: orderId },
      select: {
        id: true,
        status: true,
        payment: { select: { status: true } },
        items: { select: { porkCutId: true, kilograms: true } },
      },
    });

    if (
      !order ||
      !order.payment ||
      (order.payment.status !== "PENDING" &&
        order.payment.status !== "PROCESSING")
    ) {
      return;
    }

    await transaction.payment.update({
      where: { orderId: order.id },
      data: { status: "FAILED" },
    });

    if (order.status !== "CANCELLED") {
      await transaction.order.update({
        where: { id: order.id },
        data: { status: "CANCELLED" },
      });
    }

    for (const item of order.items) {
      await transaction.porkCut.update({
        where: { id: item.porkCutId },
        data: { availableKg: { increment: item.kilograms } },
      });
    }
  });
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
          id: true,
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

    if (input.paymentMethod === "MPESA") {
      try {
        const stkPush = await initiateDarajaStkPush({
          config: getDarajaConfig(),
          phoneNumber: input.phoneNumber,
          amount: order.total,
          orderNumber: order.orderNumber,
        });

        await prisma.payment.update({
          where: { orderId: order.id },
          data: {
            status: "PROCESSING",
            mpesaPhoneNumber: stkPush.phoneNumber,
            mpesaRequestId: stkPush.checkoutRequestId,
          },
        });

        response.status(201).json({
          orderNumber: order.orderNumber,
          status: order.status,
          subtotal: order.subtotal,
          deliveryFee: order.deliveryFee,
          total: order.total,
          paymentStatus: "PROCESSING",
          paymentMessage: stkPush.customerMessage,
        });
        return;
      } catch (error) {
        await failPaymentAndReleaseStock(order.id);
        throw error;
      }
    }

    response.status(201).json({
      orderNumber: order.orderNumber,
      status: order.status,
      subtotal: order.subtotal,
      deliveryFee: order.deliveryFee,
      total: order.total,
      paymentStatus: "PENDING",
    });
  } catch (error) {
    next(error);
  }
});

app.get(
  "/api/orders/:orderNumber/payment",
  async (request, response, next) => {
    try {
      const orderNumber = Array.isArray(request.params.orderNumber)
        ? request.params.orderNumber[0]
        : request.params.orderNumber;

      if (!orderNumber) {
        throw new ApiError(400, "Order number is required");
      }

      const order = await prisma.order.findUnique({
        where: { orderNumber },
        select: {
          orderNumber: true,
          status: true,
          payment: {
            select: {
              status: true,
              amount: true,
              mpesaReceiptNumber: true,
              mpesaPhoneNumber: true,
            },
          },
        },
      });

      if (!order) {
        throw new ApiError(404, "Order not found");
      }

      response.json({
        orderNumber: order.orderNumber,
        orderStatus: order.status,
        paymentStatus: order.payment?.status ?? "PENDING",
        amount: order.payment?.amount ?? 0,
        mpesaReceiptNumber: order.payment?.mpesaReceiptNumber ?? null,
        mpesaPhoneNumber: order.payment?.mpesaPhoneNumber ?? null,
      });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/payments/daraja/callback",
  async (request, response, next) => {
    try {
      const payload = request.body as DarajaCallback;
      const callback = payload.Body?.stkCallback;
      const checkoutRequestId =
        typeof callback?.CheckoutRequestID === "string"
          ? callback.CheckoutRequestID
          : undefined;
      const resultCode =
        typeof callback?.ResultCode === "number"
          ? callback.ResultCode
          : Number(callback?.ResultCode);

      if (!callback || !checkoutRequestId || !Number.isFinite(resultCode)) {
        response.json({ ResultCode: 0, ResultDesc: "Accepted" });
        return;
      }

      const payment = await prisma.payment.findFirst({
        where: { mpesaRequestId: checkoutRequestId },
        select: {
          id: true,
          orderId: true,
          status: true,
        },
      });

      if (!payment) {
        response.json({ ResultCode: 0, ResultDesc: "Accepted" });
        return;
      }

      if (payment.status !== "PENDING" && payment.status !== "PROCESSING") {
        response.json({ ResultCode: 0, ResultDesc: "Already processed" });
        return;
      }

      if (resultCode === 0) {
        const receiptNumber = callbackMetadataValue(
          callback,
          "MpesaReceiptNumber",
        );
        const phoneNumber = callbackMetadataValue(callback, "PhoneNumber");

        await prisma.$transaction(async (transaction) => {
          const currentPayment = await transaction.payment.findUnique({
            where: { id: payment.id },
            select: { status: true },
          });

          if (
            !currentPayment ||
            (currentPayment.status !== "PENDING" &&
              currentPayment.status !== "PROCESSING")
          ) {
            return;
          }

          await transaction.payment.update({
            where: { id: payment.id },
            data: {
              status: "PAID",
              mpesaReceiptNumber:
                receiptNumber === undefined ? undefined : String(receiptNumber),
              mpesaPhoneNumber:
                phoneNumber === undefined ? undefined : String(phoneNumber),
              paidAt: new Date(),
            },
          });

          await transaction.order.update({
            where: { id: payment.orderId },
            data: { status: "CONFIRMED" },
          });
        });
      } else {
        await failPaymentAndReleaseStock(payment.orderId);
      }

      response.json({ ResultCode: 0, ResultDesc: "Accepted" });
    } catch (error) {
      next(error);
    }
  },
);

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

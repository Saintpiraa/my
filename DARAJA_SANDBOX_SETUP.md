# Taviv Daraja Sandbox setup

The Taviv checkout now supports a full-order M-Pesa STK Push in Safaricom Daraja Sandbox. The customer phone number from checkout receives the prompt. The backend creates the order first, starts the STK request, stores the Daraja checkout request ID, and waits for the callback before marking the payment as paid. If the Sandbox payment fails, the payment is marked failed, the order is cancelled, and the reserved stock is returned.

## 1. Create a Daraja Sandbox app

Open the [Safaricom Daraja Developer Portal](https://developer.safaricom.co.ke/), create or sign in to your account, and create a Sandbox app with the M-Pesa Express/Lipa na M-Pesa product. Keep the Consumer Key, Consumer Secret, and Passkey private. The Sandbox Lipa na M-Pesa shortcode is normally `174379`; use the test values supplied by the Daraja portal if the simulator provides different values for your app.

## 2. Add these private variables to the local `.env`

Copy the names from `.env.example` into a private `.env` file. Replace only the blank values with the values from your Daraja Sandbox app.

```env
DARAJA_ENV=sandbox
DARAJA_BASE_URL=https://sandbox.safaricom.co.ke
DARAJA_CONSUMER_KEY=
DARAJA_CONSUMER_SECRET=
DARAJA_SHORTCODE=174379
DARAJA_PASSKEY=
DARAJA_TRANSACTION_TYPE=CustomerPayBillOnline
DARAJA_CALLBACK_URL=https://taviv-api.vercel.app/api/payments/daraja/callback
```

Use `CustomerPayBillOnline` for a Paybill. Use `CustomerBuyGoodsOnline` when testing a Till/Buy Goods account. Do not put these values in React files, commit the `.env` file, or send them in chat.

## 3. Add the same private variables to Vercel

In the Vercel project settings for `taviv-api`, add the same variables to the **Production** environment. After saving them, redeploy the backend. The callback URL above is already public HTTPS and points to the Taviv payment callback route.

## 4. Test the flow

Start the local backend and frontend, or use the online storefront. Add an item to the cart, enter a valid Sandbox test phone number, and choose the full order payment. The customer should see a message telling them to check their phone. After the Sandbox callback arrives, the payment should change from processing to paid and the order should become confirmed in the admin dashboard.

The integration does not test with real customer money. Before switching to production, confirm the client’s approved Paybill or Till account, production passkey, registered production callback requirements, and go-live approval in Daraja.

## Important backend routes

- `POST /api/orders` creates the order and initiates STK Push for `paymentMethod: "MPESA"`.
- `GET /api/orders/:orderNumber/payment` returns the current payment state for the customer confirmation screen.
- `POST /api/payments/daraja/callback` receives the Safaricom callback and updates the Payment and Order records.

Reference: [Safaricom M-Pesa Express documentation](https://developer.safaricom.co.ke/apis/MpesaExpressSimulate)

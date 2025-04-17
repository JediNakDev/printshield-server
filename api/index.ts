import { Hono } from "hono";
import { handle } from "hono/vercel";
import { z } from "zod";
import { errorTable } from "./db/schema";
import { db } from "./db";
import { eq, desc, and } from "drizzle-orm";
const app = new Hono().basePath("/api");

app.get("/", (c) => {
  return c.text("PrintShield Server Running");
});

const cameraBodySchema = z.object({
  printerId: z.number(),
  isError: z.boolean(),
});

const filamentBodySchema = z.object({
  printerId: z.number(),
  isError: z.boolean(),
  filamentId: z.number(),
});

app.post("/camera", async (c) => {
  const body = await c.req.json();
  const { success, data, error } = cameraBodySchema.safeParse(body);
  if (!success) {
    return c.json({
      success,
      message: "Invalid body",
      error,
    });
  }

  if (!data.isError) {
    return c.json({ success, data });
  }

  const text = `Printer ${data.printerId} is having a printing error (From Printshield Camera)`;
  const url = `https://api.telegram.org/bot7699799142:AAFOwjQTbBUMvJbLe5MC5iYXEdltdqgl0Gc/sendMessage?chat_id=-1002584756620&text=${text}`;
  await fetch(url);
  await db.insert(errorTable).values({
    printerId: data.printerId,
    type: "camera",
    isError: data.isError,
  });
  return c.json({
    success,
    data,
  });
});

app.post("/filament", async (c) => {
  const body = await c.req.json();
  const { success, data, error } = filamentBodySchema.safeParse(body);
  if (!success) {
    return c.json({
      success,
      message: "Invalid body",
      error,
    });
  }

  if (!data.isError) {
    return c.json({ success, data });
  }
  const text = `Printer ${data.printerId}, filament ${data.filamentId} has low filament (From Printshield Filament Sensor)`;
  const url = `https://api.telegram.org/bot7699799142:AAFOwjQTbBUMvJbLe5MC5iYXEdltdqgl0Gc/sendMessage?chat_id=-1002584756620&text=${text}`;
  await fetch(url);
  await db.insert(errorTable).values({
    printerId: data.printerId,
    type: "filament",
    isError: data.isError,
  });
  return c.json({
    success,
    data,
  });
});

app.get("/error", async (c) => {
  const { printerId: printerIdString } = c.req.query();
  const printerId = parseInt(printerIdString);

  const cameraErrors = await db
    .select()
    .from(errorTable)
    .where(and(eq(errorTable.printerId, printerId), eq(errorTable.type, "camera")))
    .orderBy(desc(errorTable.createdAt))
    .limit(1);

  const filamentErrors = await db
    .select()
    .from(errorTable)
    .where(and(eq(errorTable.printerId, printerId), eq(errorTable.type, "filament")))
    .orderBy(desc(errorTable.createdAt))
    .limit(1);

  const lastCameraError = cameraErrors[0];
  const lastFilamentError = filamentErrors[0];
  const now = new Date();
  const oneMinuteAgo = new Date(now.getTime() - 3 * 1000); // 1 minute ago

  return c.json({
    isCameraError: lastCameraError && lastCameraError.createdAt > oneMinuteAgo,
    isFilamentError: lastFilamentError && lastFilamentError.createdAt > oneMinuteAgo,
  });
});

const handler = handle(app);

export const GET = handler;
export const POST = handler;
export const PATCH = handler;
export const PUT = handler;
export const OPTIONS = handler;

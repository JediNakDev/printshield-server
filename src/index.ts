import { Hono } from "hono";
import { z } from "zod";
import { errorTable } from "./db/schema";
import { db } from "./db";
const app = new Hono();

app.get("/", (c) => {
  return c.text("PrintShield Server Running");
});

const bodySchema = z.object({
  printerId: z.number(),
  isError: z.boolean(),
});

app.post("/camera", async (c) => {
  const body = await c.req.json();
  const { success, data, error } = bodySchema.safeParse(body);
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

  const text = `${data.printerId} is having a printing error (From Printshield Camera)`;
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
  const { success, data, error } = bodySchema.safeParse(body);
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
  const text = `${data.printerId} has low filament (From Printshield Filament Sensor)`;
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

export default app;

import { sql } from "drizzle-orm";
import { integer, pgTable, timestamp, boolean, pgEnum, index } from "drizzle-orm/pg-core";

export const errorType = pgEnum("error_type", ["camera", "filament"]);

export const errorTable = pgTable("error_table", {
  id: integer("id").primaryKey().generatedByDefaultAsIdentity(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .default(sql`CURRENT_TIMESTAMP`)
    .notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).$onUpdate(() => new Date()),
  type: errorType("type").notNull(),
  printerId: integer().notNull(),
  filamentId: integer(),
  isError: boolean().notNull(),
});

export type Error = typeof errorTable.$inferSelect;

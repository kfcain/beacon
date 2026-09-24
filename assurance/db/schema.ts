import {sqliteTable,text,integer} from 'drizzle-orm/sqlite-core';
export const workspaces=sqliteTable('beacon_workspaces',{owner:text('owner').primaryKey(),revision:integer('revision').notNull().default(0),body:text('body').notNull(),updatedAt:text('updated_at').notNull()});

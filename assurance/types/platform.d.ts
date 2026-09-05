// Narrow contracts for bindings used by this application. Deployment owns values.
interface Fetcher { fetch(request: Request): Promise<Response>; }
interface D1Result<T = unknown> { results: T[]; success: boolean; meta: {changes:number; [key:string]:unknown}; }
interface D1PreparedStatement {
 bind(...values:unknown[]):D1PreparedStatement;
 first<T=unknown>(column?:string):Promise<T|null>;
 all<T=unknown>():Promise<D1Result<T>>;
 run<T=unknown>():Promise<D1Result<T>>;
 raw<T=unknown[]>():Promise<T[]>;
}
interface D1Database {
 prepare(sql:string):D1PreparedStatement;
 batch<T=unknown>(statements:D1PreparedStatement[]):Promise<D1Result<T>[]>;
 exec(sql:string):Promise<{count:number;duration:number}>;
 dump():Promise<ArrayBuffer>;
}
declare module 'cloudflare:workers' { export const env:{DB:D1Database;[key:string]:unknown}; }

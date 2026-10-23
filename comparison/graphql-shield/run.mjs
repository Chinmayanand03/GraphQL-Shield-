// Baseline for comparison: the demo application's exact schema
// (../schema.graphql) and seed data, with resolvers that, like the demo,
// contain no ownership checks, protected by graphql-shield rules written the
// way its documentation recommends.
//
//   node run.mjs <variant> <scenarios.json>
//
// variant: "complete" | "fallback_deny" | "without:<rule key>"
// Prints one JSON array: for each scenario, the raw response(s) and the state of
// the victim object afterwards. Judging happens in scripts/run_tool_comparison.py,
// with the same oracle used for GraphQL Shield.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import util from "node:util";

// graphql-shield 7.6.5 calls util.isUndefined, which Node 23+ removed. Restore it
// and load every library's CommonJS build (graphql-shield looks it up at call
// time, and mixing ESM and CommonJS copies breaks graphql-middleware's checks).
util.isUndefined ??= (value) => value === undefined;
const require = createRequire(import.meta.url);
const { graphql } = require("graphql");
const { makeExecutableSchema } = require("@graphql-tools/schema");
const { applyMiddleware } = require("graphql-middleware");
const { allow, deny, rule, shield } = require("graphql-shield");

const [variant = "complete", scenarioFile] = process.argv.slice(2);
const typeDefs = readFileSync(new URL("../schema.graphql", import.meta.url), "utf8");
const scenarios = JSON.parse(readFileSync(scenarioFile, "utf8"));
const VICTIM = 102;

// Mirrors app/seed.py plus the shared-folder object 204.
function seed() {
  return {
    users: new Map([
      [101, { id: 101, username: "balanilavan", role: "user" }],
      [102, { id: 102, username: "kapilesh", role: "user" }],
      [103, { id: 103, username: "sakthivel", role: "user" }],
      [104, { id: 104, username: "chinmayanand", role: "admin" }],
    ]),
    objects: new Map(
      [
        [101, "document", 101, "Balanilavan's Secret Note", null],
        [102, "document", 102, "Kapilesh's Financial Record", null],
        [103, "document", 103, "Sakthivel B's Research Note", null],
        [104, "document", 104, "Chinmayanand's Admin Log", null],
        [201, "folder", 101, "Balanilavan's Projects", null],
        [202, "document", 101, "Project Alpha Plan", 201],
        [203, "document", 101, "Project Beta Plan", 201],
        [204, "document", 102, "Kapilesh's Shared Draft", 201],
      ].map(([id, objectType, ownerId, name, parentId]) => [id, { id, objectType, ownerId, name, parentId }]),
    ),
  };
}

let db = seed();
const children = (id) => [...db.objects.values()].filter((o) => o.parentId === id);

const resolvers = {
  Query: {
    health: () => ({ status: "ok", message: "GraphQL API is healthy" }),
    user: (_, { id }) => db.users.get(id) ?? null,
    resource: (_, { id }) => db.objects.get(id) ?? null,
  },
  UserType: {
    resources: (user) => [...db.objects.values()].filter((o) => o.ownerId === user.id),
    resource: (_, { id }) => db.objects.get(id) ?? null,
  },
  ResourceType: {
    children: (resource) => children(resource.id),
    childrenCount: (resource) => children(resource.id).length,
  },
  Mutation: {
    updateResource: (_, { id, name }) => {
      const object = db.objects.get(id);
      if (object) object.name = name;
      return object ?? null;
    },
    deleteResource: (_, { id }) => (children(id).length ? false : db.objects.delete(id)),
    transferOwnership: (_, { id, newOwnerId }) => {
      const object = db.objects.get(id);
      if (object && db.users.has(newOwnerId)) object.ownerId = newOwnerId;
      return object ?? null;
    },
  },
};

// ---------------------------------------------------------------- rules
const isAdmin = (ctx) => ctx.user.role === "admin";
const ownsResource = (ctx, id) => isAdmin(ctx) || db.objects.get(id)?.ownerId === ctx.user.id;
const isUser = (ctx, id) => isAdmin(ctx) || id === ctx.user.id;

const ownsResourceArg = rule({ cache: "no_cache" })((_, args, ctx) => ownsResource(ctx, args.id));
const isUserArg = rule({ cache: "no_cache" })((_, args, ctx) => isUser(ctx, args.id));
const ownsParentResource = rule({ cache: "no_cache" })((parent, _, ctx) => ownsResource(ctx, parent.id));
const isParentUser = rule({ cache: "no_cache" })((parent, _, ctx) => isUser(ctx, parent.id));

// Each key is one permission entry a developer has to write and maintain.
const RULES = {
  "Query.user": ["Query", "user", isUserArg],
  "Query.resource": ["Query", "resource", ownsResourceArg],
  "UserType.resource": ["UserType", "resource", ownsResourceArg],
  "UserType.*": ["UserType", "*", isParentUser],
  "ResourceType.*": ["ResourceType", "*", ownsParentResource],
  "Mutation.updateResource": ["Mutation", "updateResource", ownsResourceArg],
  "Mutation.deleteResource": ["Mutation", "deleteResource", ownsResourceArg],
  "Mutation.transferOwnership": ["Mutation", "transferOwnership", ownsResourceArg],
};

// variant: "complete", "fallback_deny", "without:<rule>", or "fallback_deny,without:<rule>"
function permissions(variant) {
  const parts = variant.split(",");
  const variantName = parts.includes("fallback_deny") ? "fallback_deny" : "complete";
  const removed = parts.find((p) => p.startsWith("without:"))?.slice("without:".length) ?? null;
  const tree = {};
  for (const [key, [type, field, check]] of Object.entries(RULES)) {
    if (key === removed) continue;
    tree[type] ??= {};
    tree[type][field] = check;
  }
  if (variantName === "fallback_deny") {
    // Default-deny: every field not covered above must be allowed explicitly.
    tree.Query = { ...tree.Query, health: allow };
    tree.HealthCheckType = allow;
  }
  return shield(tree, {
    fallbackRule: variantName === "fallback_deny" ? deny : allow,
    allowExternalErrors: false,
  });
}

const schema = applyMiddleware(makeExecutableSchema({ typeDefs, resolvers }), permissions(variant));

async function execute(operation, user) {
  const result = await graphql({
    schema,
    source: operation.query,
    variableValues: operation.variables,
    operationName: operation.operationName,
    contextValue: { user },
  });
  const payload = { data: result.data ?? null };
  if (result.errors?.length) payload.errors = result.errors.map((e) => ({ message: e.message }));
  return payload;
}

const results = [];
for (const scenario of scenarios) {
  db = seed();
  const user = { id: scenario.user, role: scenario.role };
  const operations = Array.isArray(scenario.body) ? scenario.body : [scenario.body];
  const responses = [];
  for (const operation of operations) responses.push(await execute(operation, user));
  const victim = db.objects.get(VICTIM);
  results.push({
    scenario: scenario.name,
    variant,
    responses,
    victim: victim ? { name: victim.name, ownerId: victim.ownerId } : null,
  });
}
process.stdout.write(JSON.stringify(results));

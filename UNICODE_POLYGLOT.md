# Unicode SQL & Polyglot Injection Detection

## Version 1.3.2 Features

### 🎯 Unicode SQL Injection Detection

Detects sophisticated SQL injection attacks using Unicode encoding to bypass traditional filters.

#### Detection Types:

1. **Full-Width Characters**
   ```
   ＳＥＬＥＣＴ * FROM users
   ```
   - Detects: `[\uFF03-\uFF5E]`
   - Full-width Unicode that looks like normal ASCII

2. **Cyrillic Homoglyphs**
   ```
   SЕLЕCT * FROM users  (Е is Cyrillic E)
   ```
   - Detects: `[ЅЕLЕСТІОNUΝІОN]`
   - Visually identical to Latin characters

3. **Cherokee Lookalikes**
   ```
   ᏚᎬᏞᎬᏟᎢ * FROM users
   ```
   - Detects: `[ᏚᎬᏞᎬᏟᎢ]`
   - Cherokee characters that look like SELECT

4. **Unicode Code Points**
   ```
   \u0053\u0045\u004C\u0045\u0043\u0054  (SELECT)
   \u0055\u004E\u0049\u004F\u004E      (UNION)
   \u0044\u0052\u004F\u0050            (DROP)
   ```

#### Why It Matters:

Attackers use Unicode to bypass simple keyword filters:
- WAFs that only check ASCII
- Basic blacklist filters
- Case-insensitive simple regex

### 💥 Polyglot Injection Detection

Detects attacks that work as **BOTH** SQL injection AND XSS simultaneously.

#### Attack Examples:

1. **Classic Polyglot**
   ```
   ' OR 1=1--<script>alert(1)</script>
   ```
   Works as:
   - **SQL**: `' OR 1=1--` (SQL comment hides the rest)
   - **XSS**: `<script>alert(1)</script>` (executes in browser)

2. **UNION with XSS**
   ```
   ' UNION SELECT '<script>alert(1)</script>'--
   ```
   - SQL injects a script tag into query results
   - When rendered in HTML, executes JavaScript

3. **Event Handler Polyglot**
   ```
   <img src=x onerror="x=' OR 1=1--">
   ```
   - **XSS**: `onerror` event handler
   - **SQL**: Embedded SQL injection in the script

4. **JavaScript Protocol**
   ```
   javascript:alert(SELECT * FROM users)
   ```

5. **SVG Polyglot**
   ```
   <svg onload="x=' UNION SELECT password FROM users--">
   ```

6. **Data URI**
   ```
   data:text/html,<script>x=' UNION SELECT *--</script>
   ```

#### Detection Patterns (15+):

```typescript
/'><script/i                    // Quote + XSS tag
/'\s*OR\s+.*<script/i          // SQL OR + XSS
/UNION.*<script/i              // UNION + XSS
/<script>.*SELECT/i            // XSS + SQL
/<script>.*UNION/i             // XSS + UNION
/<script>.*INSERT/i            // XSS + INSERT
/<img.*onerror.*['"].*OR/i     // XSS event + SQL
/<svg.*onload.*SELECT/i        // SVG + SQL
/javascript:.*SELECT/i         // js: protocol + SQL
/data:text\/html.*<script>.*SQL/i  // Data URI + both
```

## 📊 Test Results

### All Tests Passing ✅

```
Polyglot Tests: 18/18 passing
- 6 polyglot detection tests
- 4 Unicode SQL detection tests
- 3 edge case tests
- 5 complex polyglot tests

Existing Tests: 54/54 passing
- 20 serverless compatibility
- 11 access control
- 23 false positive prevention

Total: 72 tests passing
```

### Example Test Cases:

```javascript
// ✅ DETECTS: Polyglot attacks
"' OR 1=1--<script>alert(1)</script>"
"' UNION SELECT '<img src=x onerror=alert(1)>'--"
"<svg onload=\"x=' UNION SELECT password FROM users--\">"

// ✅ DETECTS: Unicode SQL
"ＳＥＬＥＣＴ * FROM users"
"SЕLЕCT * FROM users" // Cyrillic Е
"ᏚᎬᏞᎬᏟᎢ OR 1=1--"     // Cherokee

// ✅ ALLOWS: Normal content
"It's a nice day"
"Hello 世界 мир"
"<div>Hello World</div>"
```

## 🔧 Implementation Details

### High-Confidence Detection

**Unicode SQL patterns are HIGH confidence:**
- Only 1 Unicode pattern match needed (vs 2 for normal SQL)
- Intentional encoding = likely malicious
- Low false positive rate

**Polyglot patterns are CRITICAL severity:**
- 2+ patterns = Critical
- Indicates sophisticated attack
- Requires immediate blocking

### Metadata

Detection results include detailed metadata:

```typescript
{
  type: 'SQL_INJECTION',
  severity: 'critical',
  description: 'Potential Unicode SQL injection detected (confidence: 85%)',
  payload: 'ＳＥＬＥＣＴ * FROM users',
  confidence: 85,
  metadata: {
    attackType: 'unicode-sql',
    unicodeDetected: true,
    matchCount: 3
  }
}
```

### Integration

Both detections are **automatic** - no configuration needed:

```javascript
const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true
  }
});

// Automatically detects Unicode SQL and Polyglot attacks
const result = aimless.validate(userInput).against(['all']).result();

if (!result.safe) {
  // result.threats contains Unicode/Polyglot threat details
  console.log('Attack detected:', result.threats);
}
```

## 🎯 Real-World Impact

### What This Protects Against:

1. **WAF Bypasses**: Attackers encoding SQL to evade WAFs
2. **Filter Evasion**: Unicode homoglyphs bypass keyword filters
3. **Double Exploitation**: Single payload exploits two vulnerabilities
4. **Advanced Attackers**: Indicates sophisticated threat actor

### Attack Scenarios:

**Scenario 1: Unicode Filter Bypass**
```
Attacker: ＳＥＬＥＣＴ password FROM users
Basic WAF: ✅ Allowed (doesn't recognize full-width)
Aimless SDK: 🛑 BLOCKED (Unicode SQL detected)
```

**Scenario 2: Polyglot in Search**
```
User Search: ' OR 1=1--<script>alert(document.cookie)</script>
SQL Result: Returns all records (SQL injection works)
HTML Display: Executes script (XSS also works)
Aimless SDK: 🛑 BLOCKED (Polyglot detected, critical severity)
```

## 📚 Resources

- [OWASP Unicode Security Guide](https://owasp.org/www-community/attacks/Unicode_Security)
- [Polyglot Injection Research](https://portswigger.net/research/polygot-payloads)
- [Homoglyph Attack Techniques](https://owasp.org/www-project-web-security-testing-guide/)

## 📦 Installation

```bash
npm install CamozDevelopment/Aimless-Security
```

## 🚀 Quick Start

```javascript
const { Aimless } = require('aimless-security');

const aimless = new Aimless({
  rasp: {
    blockMode: true,
    injectionProtection: true,
    xssProtection: true
  }
});

// Test Unicode SQL
const result1 = aimless.validate('ＳＥＬＥＣＴ').against(['sql']).result();
console.log('Unicode SQL:', !result1.safe); // true (detected)

// Test Polyglot
const result2 = aimless.validate("' OR 1=1--<script>alert(1)</script>")
  .against(['all'])
  .result();
console.log('Polyglot:', !result2.safe); // true (detected)
console.log('Severity:', result2.threats[0]?.severity); // 'critical'
```

## 🏆 Version History

- **v1.3.2** - Unicode SQL + Polyglot detection (18 new tests)
- **v1.3.1** - Advanced threat detection (LDAP, Template, JWT, GraphQL)
- **v1.3.0** - Access control system (allowlist/blocklist)
- **v1.2.0** - Default blockMode changed to false
- **v1.1.2** - Serverless compatibility fix

---

**aimless-security v1.3.2** - Advanced RASP with Unicode SQL and Polyglot Injection Detection

# Engineering Principles

**Purpose:** Core engineering principles that guide all development in this codebase.

**Audience:** All developers, AI assistants, code reviewers

**Status:** Living document - updated as we learn

---

## 🧭 Core Philosophy

> **"Optimize for clarity and adaptability, not perfection."**

This codebase prioritizes:
- ✅ **Maintainable** - Easy to understand and change
- ✅ **Evolvable** - Adaptable to new requirements
- ✅ **Documented** - Clear context for future developers
- ❌ **NOT Perfect** - Good enough is better than perfect

---

## 🎯 Guiding Principles

### 1. KISS – Keep It Simple, Stupid

**Rule:** The simplest solution that works is the best solution.

**In Practice:**
- Favor clarity over cleverness
- Break complex logic into small, understandable pieces
- Avoid over-engineering and premature optimization
- No "clever" code that sacrifices readability

**Example:**
```javascript
// ❌ BAD: Clever but hard to understand
const result = data.reduce((acc, x) => ({ ...acc, [x.id]: x }), {});

// ✅ GOOD: Clear and explicit
const result = {};
for (const item of data) {
  result[item.id] = item;
}
```

**Anti-Perfection Rule:** Prefer clear, working solutions over complex "perfect" ones.

---

### 2. DRY – Don't Repeat Yourself

**Rule:** Every piece of knowledge should have a single, unambiguous representation.

**In Practice:**
- Extract common logic into reusable functions/modules
- Externalize configuration (don't hardcode)
- Define constants for magic numbers
- Share types/interfaces across modules

**Example:**
```javascript
// ❌ BAD: Repeated validation logic
function createUser(email) {
  if (!email.includes('@')) throw new Error('Invalid email');
  // ...
}
function updateUser(email) {
  if (!email.includes('@')) throw new Error('Invalid email');
  // ...
}

// ✅ GOOD: Reusable validation
function validateEmail(email) {
  if (!email.includes('@')) throw new Error('Invalid email');
}

function createUser(email) {
  validateEmail(email);
  // ...
}
```

**Note:** DRY applies to *knowledge* and *business logic*, not necessarily code. Sometimes duplication is better than the wrong abstraction.

---

### 3. YAGNI – You Ain't Gonna Need It

**Rule:** Only implement features you actually need right now.

**In Practice:**
- Don't add functionality "just in case"
- No speculative features or abstractions
- Remove unused code and commented-out blocks
- Avoid over-abstraction

**Example:**
```javascript
// ❌ BAD: Building for future features we don't need yet
class UserService {
  async createUser() { /* ... */ }
  async updateUser() { /* ... */ }
  async deleteUser() { /* ... */ }
  async restoreUser() { /* ... */ }  // Not needed yet!
  async archiveUser() { /* ... */ }  // Not needed yet!
  async exportUser() { /* ... */ }   // Not needed yet!
}

// ✅ GOOD: Only what we need now
class UserService {
  async createUser() { /* ... */ }
  async updateUser() { /* ... */ }
  async deleteUser() { /* ... */ }
}
// Add other methods when actually needed
```

---

### 4. SRP – Single Responsibility Principle

**Rule:** Each function/class should have one, and only one, reason to change.

**In Practice:**
- Functions should do one thing and do it well
- Classes should have a single, clear responsibility
- No "god objects" or monolithic functions
- Clear separation of concerns

**Example:**
```javascript
// ❌ BAD: Function does too many things
async function handleUserRegistration(email, password) {
  validateEmail(email);
  validatePassword(password);
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await db.users.create({ email, password: hashedPassword });
  await emailService.sendWelcomeEmail(email);
  await analyticsService.trackRegistration(user.id);
  await auditLog.log('USER_REGISTERED', user.id);
  return user;
}

// ✅ GOOD: Each function has single responsibility
async function createUser(email, password) {
  const hashedPassword = await hashPassword(password);
  return db.users.create({ email, password: hashedPassword });
}

async function handleUserRegistration(email, password) {
  validateUserInput(email, password);
  const user = await createUser(email, password);
  await sendWelcomeEmail(user.email);
  await trackRegistration(user.id);
  await logUserCreated(user.id);
  return user;
}
```

---

### 5. High Cohesion / Low Coupling

**Rule:** Related functionality should be grouped together; modules should minimize dependencies.

**In Practice:**
- Group related functions/classes in the same module
- Minimize dependencies between modules
- Use clear interfaces/contracts
- Make modules easy to test in isolation

**Example:**
```
// ✅ GOOD: High cohesion - related things together
src/users/
├── users.service.ts       # User business logic
├── users.controller.ts    # HTTP handlers
├── users.repository.ts    # Database access
├── dto/
│   ├── create-user.dto.ts
│   └── update-user.dto.ts
└── entities/
    └── user.entity.ts

// ✅ GOOD: Low coupling - clear boundaries
UsersService depends on UsersRepository (interface)
UsersController depends on UsersService
No circular dependencies
```

---

### 6. Composition > Inheritance

**Rule:** Favor composition over inheritance for code reuse.

**In Practice:**
- Use interfaces/types for contracts
- Inject dependencies (dependency injection)
- No deep inheritance hierarchies
- Prefer "has-a" over "is-a"

**Example:**
```javascript
// ❌ BAD: Deep inheritance hierarchy
class BaseService {
  constructor(db) { this.db = db; }
}
class CRUDService extends BaseService {
  create() { /* ... */ }
  read() { /* ... */ }
}
class UserService extends CRUDService {
  /* ... */
}

// ✅ GOOD: Composition with dependency injection
class UserService {
  constructor(userRepository, auditLogger) {
    this.userRepository = userRepository;
    this.auditLogger = auditLogger;
  }

  async createUser(data) {
    const user = await this.userRepository.create(data);
    await this.auditLogger.log('USER_CREATED', user.id);
    return user;
  }
}
```

---

### 7. Law of Demeter (Principle of Least Knowledge)

**Rule:** Objects should only talk to their direct friends.

**In Practice:**
- Don't chain method calls through multiple objects
- Proper encapsulation
- No "train wrecks" (`a.b().c().d()`)

**Example:**
```javascript
// ❌ BAD: Law of Demeter violation
const city = user.getAddress().getCity().getName();

// ✅ GOOD: Ask the object to do it
const city = user.getCityName();

// Inside User class:
class User {
  getCityName() {
    return this.address.city.name;
  }
}
```

---

## 🏗️ Architecture Principles

### Clean/Hexagonal Architecture

> **Reality check:** The current codebase uses a pragmatic single-file monolith (`server.js` + `index.html`). The principles below describe the target direction for when modularization is warranted. Per YAGNI, the monolith ships value now.

**Rule:** Business logic should be independent of frameworks, UI, and infrastructure.

**Layers:**
1. **Domain** (Core) - Business logic, entities
2. **Application** - Use cases, services
3. **Infrastructure** - Database, external APIs
4. **Presentation** - Controllers, DTOs

**Dependencies flow inward:** Presentation → Application → Domain

**Example:**
```
src/
├── domain/
│   ├── entities/          # Pure business objects
│   └── interfaces/        # Contracts (repositories, etc.)
├── application/
│   └── services/          # Business logic, use cases
├── infrastructure/
│   ├── database/          # Database implementation
│   └── external/          # External API clients
└── presentation/
    └── controllers/       # HTTP handlers
```

---

### 12-Factor App Principles

**Rule:** Build cloud-native, scalable applications.

**Key Principles:**
1. ✅ **Codebase:** One codebase tracked in version control
2. ✅ **Dependencies:** Explicitly declared (package.json)
3. ✅ **Config:** Stored in environment variables (.env)
4. ✅ **Backing Services:** Attached resources (database, cache)
5. ✅ **Build/Release/Run:** Strict separation
6. ✅ **Processes:** Stateless, share-nothing
7. ✅ **Port Binding:** Self-contained services
8. ✅ **Concurrency:** Scale via process model
9. ✅ **Disposability:** Fast startup, graceful shutdown
10. ✅ **Dev/Prod Parity:** Keep environments similar
11. ✅ **Logs:** Treat as event streams (stdout)
12. ✅ **Admin Processes:** Run as one-off tasks

---

## 🔒 Security Principles

### Input Validation

**Rule:** All user input is hostile until proven otherwise.

**In Practice:**
- Validate at system boundaries (controllers)
- Use validation helpers at route boundaries
- Sanitize input
- Whitelist, don't blacklist

**Example:**
```javascript
// ✅ GOOD: Validate at the boundary
app.post('/api/users', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  if (!password || password.length < 12) return res.status(400).json({ error: 'Password too short' });
  if (!name || name.length < 2 || name.length > 50) return res.status(400).json({ error: 'Invalid name' });
  // ... proceed with validated data
});
```

---

### Explicit > Implicit

**Rule:** Be explicit in your code. No magic behavior.

**In Practice:**
- Clear function signatures with types
- Explicit error handling (no silent failures)
- JSDoc annotations for non-obvious functions
- Clear naming conventions

**Example:**
```javascript
// ❌ BAD: Implicit, unclear
function process(data) {
  // What does this return? When does it throw?
}

// ✅ GOOD: Explicit naming and JSDoc
/** @param {string} userId @returns {Promise<Object|null>} processed user or null */
async function processUserData(userId) {
  // Clear what it does, returns, and when
}
```

---

### Validated Inputs, Actionable Errors, Structured Logs

**Rule:** Validate early, fail fast, log everything.

**Validated Inputs:**
```javascript
app.post('/api/users', (req, res) => {
  const { email, password } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  // Validate before processing
});
```

**Actionable Errors:**
```javascript
// ❌ BAD: Unclear error
throw new Error('Failed');

// ✅ GOOD: Actionable error with context
return res.status(400).json({
  error: 'Email address is already in use',
  field: 'email',
  suggestion: 'Try logging in or use password reset',
});
```

**Structured Logs:**
```javascript
// ✅ GOOD: Structured logging
console.log(JSON.stringify({
  message: 'User created successfully',
  userId: user.id,
  timestamp: new Date().toISOString(),
}));
```

---

### No Secrets in Code or Logs

**Rule:** Never hardcode secrets. Never log secrets.

**In Practice:**
- All secrets in environment variables
- Secrets loaded from .env (development) or secret manager (production)
- Sanitize logs (no passwords, tokens, etc.)

**Example:**
```javascript
// ❌ BAD: Hardcoded secret
const apiKey = 'sk-1234567890abcdef';

// ✅ GOOD: Environment variable
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error('API_KEY not configured');

// ✅ GOOD: Sanitized logging
console.log('API call made:', { endpoint: '/api/users' });
// Don't log the full request with auth headers!
```

---

### Fail Fast

**Rule:** Detect errors early and explicitly.

**In Practice:**
- Validate inputs at boundaries
- No swallowed exceptions
- Throw errors early
- Don't return null when you should throw

**Example:**
```javascript
// ❌ BAD: Silent failure
function getUser(id) {
  try {
    return db.users.findById(id);
  } catch (error) {
    return null; // Swallowed error!
  }
}

// ✅ GOOD: Explicit error handling
function getUser(id) {
  const user = db.users.findById(id);
  if (!user) {
    throw new Error(`User ${id} not found`);
  }
  return user;
}
```

---

## 📚 Documentation Principles

### Documentation as Code

**Rule:** Documentation lives with code and is version controlled.

**In Practice:**
- JSDoc/TSDoc for public APIs
- README.md for modules
- Architecture diagrams in docs/
- ADRs for significant decisions

---

### Documentation Hygiene

**Rule:** Keep documentation minimal, focused, and up-to-date.

**Permanent Docs:**
- `CLAUDE.md` - Agent context (architecture, API reference, conventions)
- `PRINCIPLES.md` - This file (engineering principles)
- `README.md` - Product README (features, quick start, config)
- `handover.md` - Session handover (architecture, APIs, current state)
- `plans/productization-plan.md` - Phased product roadmap
- `plans/product-strategy.md` - Competitive analysis and go-to-market

**Policy:**
- Keep docs minimal and up-to-date
- Delete redundant/outdated files
- Consolidate rather than create new docs

---

## ✅ Testing Principles

### Test Pyramid

**Rule:** More unit tests, fewer integration tests, even fewer E2E tests.

```
       /\
      /  \     E2E Tests (Few)
     /----\
    /      \   Integration Tests (Some)
   /--------\
  /          \ Unit Tests (Many)
 /____________\
```

**Coverage Targets:**
- **Unit Tests:** Prioritize critical paths (auth, healing, billing). No test suite exists yet — adding tests is a priority.
- **Integration Tests:** Key flows (API endpoints, cron jobs)
- **E2E Tests:** Critical user journeys (login, container restart, banner creation)

---

### Test Quality

**Rule:** Tests should be readable, independent, and deterministic.

**Characteristics:**
- ✅ **Readable:** Clear test names, arrange/act/assert
- ✅ **Independent:** No shared state between tests
- ✅ **Deterministic:** Same input = same output (no flaky tests)
- ✅ **Fast:** Unit tests run in milliseconds
- ✅ **Realistic:** Test data resembles production data

**Example:**
```javascript
// Example: testing auth setup endpoint
describe('POST /api/auth/setup', () => {
  it('should create admin account with hashed password', async () => {
    // Arrange
    const payload = { username: 'admin', password: 'Test123!@#' };

    // Act
    const res = await request(app).post('/api/auth/setup').send(payload);

    // Assert
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('admin');
    // Password should be hashed in DB, not stored plain
  });

  it('should reject if admin already exists', async () => {
    // Arrange — admin was created in previous test

    // Act & Assert
    const res = await request(app).post('/api/auth/setup').send({ username: 'admin2', password: 'pass' });
    expect(res.status).toBe(400);
  });
});
```

---

## 🚀 Performance Principles

### Premature Optimization is Evil

**Rule:** Make it work, make it right, make it fast (in that order).

**In Practice:**
- Optimize only when there's a proven performance problem
- Measure first (profiling, benchmarks)
- Focus on algorithmic complexity (O(n) vs O(n²))
- Avoid micro-optimizations

---

### Performance Safeguards

**In Practice:**
- Paginate large datasets
- Index database queries appropriately
- Avoid N+1 queries
- Use caching strategically
- Set timeouts on external calls

**Example:**
```javascript
// ✅ GOOD: Pagination
app.get('/api/users', (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const users = db.prepare('SELECT * FROM users LIMIT ? OFFSET ?').all(limit, (page - 1) * limit);
  res.json({ users, page, limit });
});
```

---

## 🔄 Refactoring Principles

### Refactor Regularly

**Rule:** Leave the code better than you found it.

**When to Refactor:**
- When you touch code that's hard to understand
- When you see duplication
- When tests are hard to write
- When adding a feature feels harder than it should

**When NOT to Refactor:**
- When deadlines are tight (add TODO instead)
- When you don't understand the code yet
- When there are no tests (add tests first)

---

## 🛡️ Code Review Principles

### Self-Review First

**Rule:** Review your own code before asking others.

**Checklist:**
- [ ] KISS, DRY, YAGNI, SRP followed
- [ ] Security checklist passed
- [ ] Tests written and passing
- [ ] Documentation updated
- [ ] No debug code or console.logs
- [ ] Linter and type checker pass

---

## 🎨 Style Principles

### Consistency > Preference

**Rule:** Follow the project's existing style, even if you prefer another.

**In Practice:**
- Consistent code formatting (ESLint + Prettier not yet configured)
- Conventional commit messages
- Consistent naming conventions (camelCase functions, kebab-case files)

---

## 📊 Monitoring & Observability

### Log Everything Important

**Rule:** You can't debug what you can't see.

**What to Log:**
- ✅ Authentication events
- ✅ Authorization failures
- ✅ Errors and exceptions
- ✅ External API calls
- ✅ Database queries (slow queries)
- ✅ Business-critical actions

**What NOT to Log:**
- ❌ Passwords or secrets
- ❌ Personal data (GDPR)
- ❌ Full request/response bodies (unless debug mode)

---

## 🎯 Summary

**Core Principles:**
1. **KISS** - Simple > Clever
2. **DRY** - Don't Repeat Knowledge
3. **YAGNI** - Build What You Need Now
4. **SRP** - One Responsibility Per Component
5. **High Cohesion / Low Coupling** - Related Together, Minimal Dependencies
6. **Composition > Inheritance** - Flexible > Rigid
7. **Law of Demeter** - Talk to Friends Only

**Architecture:**
- Clean/Hexagonal Architecture
- 12-Factor App Principles

**Security:**
- Validate All Inputs
- Explicit Error Handling
- No Secrets in Code/Logs
- Fail Fast

**Documentation:**
- Documentation as Code
- Minimal, Focused, Up-to-date
- Consolidate & Clean Up

**Testing:**
- Test Pyramid (Many Unit, Some Integration, Few E2E)
- Prioritize Critical Paths
- Readable, Independent, Deterministic

**Performance:**
- Measure Before Optimizing
- Algorithmic Efficiency > Micro-optimizations
- Pagination, Indexing, Caching

**Process:**
- Self-Review First
- Refactor Regularly
- Consistency > Preference
- Log Everything Important

---

**Remember:** These are guidelines, not laws. Use judgment. The goal is **maintainable, evolvable, documented code** - not perfect code.

---

**Last Updated:** 2026-02-27
**Maintainer:** Konrad Reyhe

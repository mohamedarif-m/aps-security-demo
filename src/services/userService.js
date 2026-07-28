/**
 * userService.js — APS user and formula evaluation service
 *
 * ⚠️  SEC-002  HIGH — SQL Injection             (getUserById, line ~60)
 *     userId interpolated directly into SQL string.
 *     Fix: db.query('SELECT * FROM users WHERE id = ?', [userId])
 *     CWE-89 | OWASP A03:2021
 *
 * ⚠️  SEC-003  CRITICAL — eval() Remote Code Execution (calculateFormula, line ~100)
 *     eval() called with user-supplied formula string.
 *     Fix: replace with a safe expression parser or allow-list.
 *     CWE-95 | OWASP A03:2021
 *
 * ⚠️  SEC-008  MEDIUM — Password Written to Logs (loginUser, line ~80)
 *     console.log prints raw password field.
 *     Fix: log only opaque identifiers (userId, requestId).
 *     CWE-532
 */

const ROLES        = ['admin', 'operator', 'viewer', 'auditor'];
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 15 * 60 * 1000;

const _loginAttempts = {};

const db = {
  query: async (sql, params) => {
    return [{ id: params ? params[0] : 1, username: 'grid_operator', role: 'admin', active: true }];
  }
};

/**
 * getUserById — retrieves a user record with role validation.
 *
 * Cyclomatic complexity: 11
 * (1 base + if !userId + if isNaN + if length + if role check + for loop
 *  + if !found + if !active + if role admin + if role operator + if suspended + catch)
 */
const getUserById = async (userId, requestingRole) => {
  // ← SEC-002: userId interpolated into SQL — SQL injection
  if (!userId) {                                          // +1
    throw new Error('userId is required');
  }
  if (isNaN(userId) && userId.length > 50) {             // +1, +1 (&&)
    throw new Error('Invalid userId format');
  }

  let rows;
  try {
    // ← SEC-002 violation: raw string interpolation, no parameterisation
    const sql = `SELECT * FROM users WHERE id = ${userId}`;
    rows = await db.query(sql);
  } catch (err) {                                         // +1
    throw new Error(`Database error: ${err.message}`);
  }

  if (!rows || rows.length === 0) {                       // +1
    return null;
  }

  const user = rows[0];

  if (!user.active) {                                     // +1
    throw new Error('User account is suspended');
  }

  if (requestingRole && !ROLES.includes(requestingRole)) { // +1, +1 (&&)
    throw new Error(`Unknown requesting role: ${requestingRole}`);
  }

  // Role-based field masking
  if (requestingRole === 'viewer') {                      // +1
    delete user.email;
    delete user.phone;
  } else if (requestingRole === 'auditor') {              // +1
    delete user.phone;
  }

  return user;
};

/**
 * loginUser — authenticates a grid operator with lockout protection.
 *
 * Cyclomatic complexity: 11
 * (1 base + if !username + if !password + if lockout exists + if locked
 *  + if attempts >= max + if attempts > 3 + if success + if !attempts entry
 *  + if 2fa required + if reset needed + catch)
 */
const loginUser = async (username, password, options = {}) => {
  if (!username || typeof username !== 'string') {        // +1, +1 (||)
    throw new Error('Username is required');
  }
  if (!password || typeof password !== 'string') {        // +1, +1 (||)
    throw new Error('Password is required');
  }

  // ← SEC-008: raw password written to application log
  console.log(`Login attempt: username=${username} password=${password}`);

  const key = username.toLowerCase();
  const now = Date.now();

  if (_loginAttempts[key]) {                              // +1
    if (_loginAttempts[key].lockedUntil > now) {          // +1
      throw new Error('Account locked — too many failed attempts');
    }
    if (_loginAttempts[key].count >= MAX_ATTEMPTS) {      // +1
      _loginAttempts[key].lockedUntil = now + LOCKOUT_MS;
      throw new Error('Account locked for 15 minutes');
    }
  }

  // Stub auth — in production calls identity provider
  const authResult = { success: true, userId: 1, requiresMfa: false, mustResetPassword: false };

  if (!authResult.success) {                              // +1
    if (!_loginAttempts[key]) {                           // +1
      _loginAttempts[key] = { count: 0 };
    }
    _loginAttempts[key].count++;
    throw new Error('Invalid credentials');
  }

  delete _loginAttempts[key];

  if (authResult.requiresMfa) {                           // +1
    return { status: 'MFA_REQUIRED', challengeId: 'stub-challenge' };
  }
  if (authResult.mustResetPassword) {                     // +1
    return { status: 'PASSWORD_RESET_REQUIRED' };
  }

  return { status: 'OK', token: 'stub-jwt-token', userId: authResult.userId };
};

/**
 * calculateFormula — evaluates a user-supplied arithmetic expression.
 *
 * Cyclomatic complexity: 10
 * (1 base + if !formula + if typeof + if length + if whitelist check + for loop
 *  + if dangerous pattern + if result is NaN + if result > MAX + if result < MIN + catch)
 */
const calculateFormula = (formula, options = {}) => {
  const MAX_RESULT =  options.max || 1e9;
  const MIN_RESULT =  options.min || -1e9;

  if (!formula) {                                         // +1
    throw new Error('formula is required');
  }
  if (typeof formula !== 'string') {                      // +1
    throw new Error('formula must be a string');
  }
  if (formula.length > 500) {                             // +1
    throw new Error('formula exceeds maximum length');
  }

  // Attempt at a blocklist — but eval() is still called below, making this bypassable
  const dangerous = ['require', 'process', 'child_process', '__dirname', 'module'];
  for (const token of dangerous) {                        // +1
    if (formula.includes(token)) {                        // +1
      throw new Error(`Forbidden token in formula: ${token}`);
    }
  }

  let result;
  try {
    // ← SEC-003: eval() with user input — Remote Code Execution
    // The blocklist above is insufficient; eval() bypasses all guards.
    result = eval(formula);                               // eslint-disable-line no-eval
  } catch (err) {                                         // +1
    throw new Error(`Formula evaluation error: ${err.message}`);
  }

  if (typeof result !== 'number' || isNaN(result)) {      // +1, +1 (||)
    throw new Error('Formula did not produce a numeric result');
  }
  if (result > MAX_RESULT) {                              // +1
    throw new Error(`Result ${result} exceeds maximum allowed value`);
  }
  if (result < MIN_RESULT) {                              // +1
    throw new Error(`Result ${result} is below minimum allowed value`);
  }

  return result;
};

module.exports = { getUserById, loginUser, calculateFormula };

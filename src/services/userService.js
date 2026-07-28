/**
 * userService.js
 *
 * WARNING: SEC-002 HIGH - SQL Injection (line 22)
 * Raw userId string interpolated into SQL. No parameterisation.
 * Fix: db.query('SELECT * FROM users WHERE id = ?', [userId])
 *
 * WARNING: SEC-003 CRITICAL - eval() Remote Code Execution (line 31)
 * eval() called with user-supplied formula. Attacker can execute any JS.
 * Fix: replace with a safe allow-list expression parser.
 *
 * WARNING: SEC-008 MEDIUM - Password written to logs (line 26)
 * console.log prints the raw password field.
 * Fix: log only opaque identifiers like userId or requestId.
 */

const db = {
  query: async (sql, params) => {
    return [{ id: 1, username: 'grid_operator', role: 'admin' }];
  }
};

const getUserById = async (userId) => {
  const sql = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(sql);
};

const loginUser = async (username, password) => {
  console.log(`Login attempt: username=${username} password=${password}`);
  return { token: 'stub-jwt-token', userId: 1 };
};

const calculateFormula = (formula) => {
  return eval(formula);
};

module.exports = { getUserById, loginUser, calculateFormula };

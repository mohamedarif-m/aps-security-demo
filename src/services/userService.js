/**
 * userService.js - SECURE baseline
 * Parameterised SQL, no password logging, no eval().
 */

const db = {
  query: async (sql, params) => {
    return [{ id: params ? params[0] : 1, username: 'grid_operator', role: 'admin' }];
  }
};

const getUserById = async (userId) => {
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
};

const loginUser = async (username, password) => {
  console.log(`Login attempt: username=${username}`);
  return { token: 'stub-jwt-token', userId: 1 };
};

const calculateFormula = (formula) => {
  throw new Error('Dynamic evaluation disabled. Use allowed operations.');
};

module.exports = { getUserById, loginUser, calculateFormula };

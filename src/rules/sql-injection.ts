/**
 * SQL INJECTION  (CWE-89, OWASP A05:2025 - Injection)
 *
 * WHAT THE BUG IS, in plain language:
 * A database doesn't receive "a question" - it receives a string of text that it
 * reads as INSTRUCTIONS. If you build that string by gluing user input into it,
 * the user gets to write part of your instructions.
 *
 *     db.query("SELECT * FROM users WHERE id = " + userId)
 *
 * If someone sends `userId = 1 OR 1=1`, the database is asked for every user.
 * If they send `1; DROP TABLE users --`, it may be asked to delete the table.
 * The database is not tricked or hacked; it does exactly what the text says.
 * The mistake happened when data and instructions were mixed into one string.
 *
 * THE FIX, so the rule can suggest it:
 * Parameterised queries (also called prepared statements). You send the query
 * shape and the values SEPARATELY:
 *
 *     db.query("SELECT * FROM users WHERE id = ?", [userId])
 *
 * The driver never lets the value become part of the instruction, whatever it
 * contains. This is not "escaping harder" - it is a structurally different
 * thing, and it is why "we sanitise our inputs" is a weaker answer than
 * "we parameterise our queries".
 *
 * WHAT THIS RULE ACTUALLY CHECKS (and does not):
 * We look for a call to a known query-executing method whose argument was
 * BUILT rather than written, and whose visible text looks like SQL. We do NOT
 * know whether the spliced-in value came from an attacker. That is data-flow
 * analysis. The taint engine does exactly that, and when it succeeds the
 * verified finding supersedes this one. Everything the tracer could not confirm
 * stays here, signature-based, saying so on the finding itself.
 */

import type { LanguageId } from '../parse/languages.js';
import { asAssignment, asCall, type Rule, type RuleHit } from './contract.js';
import {
  analyzeStringExpression,
  isStringBuildingExpression,
  looksLikeSql,
  expandsOnlyPlaceholders,
  constantProof,
} from './lib/strings.js';
import { partsAreGuarded } from './lib/guards.js';

/**
 * Methods that hand a string to a database engine.
 * Case matters: Go and Java capitalise, JavaScript and Python do not.
 */
const QUERY_METHODS: Record<LanguageId, readonly string[]> = {
  javascript: [
    'query', 'execute', 'exec', 'raw', 'prepare', 'run', 'all', 'get', 'each',
    'queryRaw', '$queryRawUnsafe', '$executeRawUnsafe', 'unsafe', 'sequelize.query',
  ],
  typescript: [
    'query', 'execute', 'exec', 'raw', 'prepare', 'run', 'all', 'get', 'each',
    'queryRaw', '$queryRawUnsafe', '$executeRawUnsafe', 'unsafe',
  ],
  python: [
    'execute', 'executemany', 'executescript', 'raw', 'text', 'query', 'from_statement',
  ],
  java: [
    'executeQuery', 'executeUpdate', 'execute', 'prepareStatement', 'prepareCall',
    'createQuery', 'createNativeQuery', 'createSQLQuery', 'rawQuery', 'addBatch',
    'queryForObject', 'queryForList', 'update',
  ],
  go: [
    'Query', 'QueryRow', 'QueryContext', 'QueryRowContext', 'Exec', 'ExecContext',
    'Prepare', 'PrepareContext', 'Raw', 'MustExec', 'Select', 'Get', 'NamedExec',
  ],
  // PHP mixes procedural functions (mysqli_query) with PDO/mysqli methods
  // ($pdo->query). Both are bare names by the time the shape reaches us, so
  // one list covers both. `prepare` is included on purpose: a prepared
  // statement built by concatenation is not parameterised, it is just a slower
  // injection.
  php: [
    'query', 'exec', 'prepare', 'unprepared', 'statement', 'select', 'selectOne',
    'mysqli_query', 'mysqli_real_query', 'mysqli_multi_query', 'mysqli_prepare',
    'pg_query', 'pg_send_query', 'sqlite_query', 'sqlsrv_query',
    'mysql_query', 'db_query',
  ],
  /*
   * C database APIs are plain functions, not methods, and every one of them
   * takes the SQL as a bare char* - there is no query builder to be confused
   * with. The parameterised forms have DIFFERENT names (mysql_stmt_prepare,
   * PQexecParams, sqlite3_prepare_v2), so they are absent here and the correct
   * code stays quiet, which is the same distinction the other languages draw
   * between `query` and `prepare`.
   */
  c: [
    'mysql_query', 'mysql_real_query', 'PQexec', 'sqlite3_exec',
    'sqlite3_get_table', 'dbsqlexec', 'SQLExecDirect',
  ],
  // C++ adds the method-call forms that wrapper libraries expose.
  cpp: [
    'mysql_query', 'mysql_real_query', 'PQexec', 'sqlite3_exec',
    'sqlite3_get_table', 'SQLExecDirect',
    'query', 'execute', 'exec',
  ],
};

const METHOD_SETS: Record<LanguageId, ReadonlySet<string>> = {
  javascript: new Set(QUERY_METHODS.javascript),
  typescript: new Set(QUERY_METHODS.typescript),
  python: new Set(QUERY_METHODS.python),
  java: new Set(QUERY_METHODS.java),
  go: new Set(QUERY_METHODS.go),
  php: new Set(QUERY_METHODS.php),
  c: new Set(QUERY_METHODS.c),
  cpp: new Set(QUERY_METHODS.cpp),
};

const MECHANISM_WORDS: Record<string, string> = {
  concatenation: 'string concatenation (+)',
  interpolation: 'string interpolation (template literal / f-string)',
  'format-call': 'a string-formatting call (Sprintf / .format / String.format)',
  opaque: 'a variable whose contents we cannot see here',
};

export const sqlInjectionRule: Rule = {
  id: 'sql-injection',
  name: 'SQL query assembled from a built string',
  cwe: 'CWE-89',
  owasp: 'A05:2025 Injection',
  severity: 'critical',
  explanation:
    'A database reads the string you give it as instructions, not as a question. ' +
    'When a query is glued together from pieces, anything spliced in can change what ' +
    'the query does - reading other users\' rows, bypassing a login check, or deleting ' +
    'a table. The fix is parameterised queries: send the query and the values ' +
    'separately, so a value can never be read as an instruction.',
  limitations:
    'UNVERIFIED (signature-based): we confirmed the query string was built rather than ' +
    'written literally. We did NOT confirm that any part of it is attacker-controlled. ' +
    'If every spliced value is a hard-coded constant or an internal enum, this is safe ' +
    'and is a false positive. When the data-flow engine CAN confirm the source, the ' +
    'finding is upgraded to flow-verified and this text is replaced by a traced path. ' +
    'When every spliced value is PROVABLY a fixed literal - including a write in a ' +
    'branch that cannot run, a condition decided at compile time, or a same-file Java ' +
    'helper reached through `new X().m()` or a private/static method - the guess is ' +
    'withdrawn and listed as proved clean with the reason, rather than reported. That ' +
    'proof stops at one helper level, does not follow helpers outside Java, and does not ' +
    'model String or collection methods, so a value fixed by any of those is still ' +
    'reported here.',
  shapes: ['call', 'assignment'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Covers node-postgres, mysql/mysql2, sqlite3, knex .raw, Prisma $queryRawUnsafe, Sequelize .query.',
    },
    typescript: {
      status: 'implemented',
      note: 'Same coverage as JavaScript; type annotations are ignored because a `string` type says nothing about trust.',
    },
    python: {
      status: 'implemented',
      note: 'Covers DB-API cursor.execute/executemany, SQLAlchemy text()/raw(). ORM query-builder misuse is not modelled.',
    },
    java: {
      status: 'implemented',
      note: 'Covers JDBC Statement/PreparedStatement, JPA createQuery/createNativeQuery, Spring JdbcTemplate. StringBuilder.append chains that build SQL over several statements are NOT followed: the tracer tracks variables, not the interior of a mutable object.',
    },
    go: {
      status: 'implemented',
      note: 'Covers database/sql and sqlx. Go code frequently builds SQL with fmt.Sprintf even when every value is a constant, so the signature pass is noisier here than elsewhere - the data-flow engine is what separates the real ones.',
    },
    php: {
      status: 'implemented',
      note: 'Covers PDO and mysqli in both their forms - the procedural functions (mysqli_query, pg_query) and the object methods ($pdo->query, ->prepare). `prepare` is watched on purpose: a prepared statement whose SQL was concatenated is not parameterised, it is a slower injection. NOT covered: an ORM that builds SQL inside its own package, and .blade.php / .twig templates, which are not parsed.',
    },
    c: {
      status: 'implemented',
      note:
        'Covers the C database APIs, which are plain functions taking the statement as a bare char*: mysql_query, mysql_real_query, PQexec, sqlite3_exec, sqlite3_get_table and SQLExecDirect. The parameterised forms have DIFFERENT names (mysql_stmt_prepare, PQexecParams, sqlite3_prepare_v2) so correct code stays quiet. Queries are almost always built by sprintf into a char buffer, which the out-parameter tracking follows.',
    },
    cpp: {
      status: 'implemented',
      note:
        'Every C entry applies unchanged, since C++ inherits the whole libc surface and real code still uses it. Namespace-qualified calls (std::system) and method calls on objects are recognised in addition.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const language = ctx.language;

    /* ---- Case 1: the query text is visible right at the call site ---- */
    const call = asCall(shape);
    if (call) {
      if (!METHOD_SETS[language].has(call.calleeName)) return null;

      for (const arg of call.args) {
        // Only look at arguments that could BE a string. An options object
        // `{ text: "...", values: [...] }` is a container, not a query.
        if (!isStringBuildingExpression(arg, language)) continue;
        const built = analyzeStringExpression(arg, language);
        // Two conditions, both required:
        //   1. the string was assembled, not written whole, and
        //   2. what we CAN read of it actually looks like SQL.
        // Condition 2 is what stops us shouting about `log("hi " + name)`.
        if (!built.isDynamic) continue;
        if (!looksLikeSql(built.literalText)) continue;
        // "Assembled" from values that are all fixed literals is not assembled
        // in any way a reader cares about. When saying so took reasoning - a
        // branch that cannot run, a condition fixed at compile time - the
        // withdrawal leaves a receipt, because reasoning can be wrong.
        const argProof = constantProof(arg, built.dynamicParts, language);
        if (argProof) {
          if (argProof.reasoned) ctx.noteClean?.('sql-injection', arg, argProof.reason);
          continue;
        }
        /*
         * A VALIDATION GUARD. `is_numeric($octet[0])` transforms nothing, so the
         * sanitiser model never saw it - but inside the branch it guards, the
         * value provably holds no metacharacter. This is DVWA's own fix for
         * command injection, and reporting it was the seventh time this project
         * punished a corrected file. See lib/guards.ts for how narrow the list is.
         */
        if (partsAreGuarded(arg, built.dynamicParts, language)) continue;
        // `${new Array(n).fill('(?,?)').join(',')}` expands to placeholders,
        // never to data. Reporting it punishes the correct bulk-insert form.
        if (built.dynamicParts.every((part) => expandsOnlyPlaceholders(part))) continue;

        const how = MECHANISM_WORDS[built.mechanism] ?? built.mechanism;
        return {
          node: arg,
          message: `SQL passed to ${call.calleeText}() is built with ${built.mechanism}`,
          reasoning:
            `\`${call.calleeText}()\` is a database query method. Its argument is not a ` +
            `fixed string - it was assembled using ${how}. The literal part reads like SQL ` +
            `("${built.literalText.replace(/\s+/g, ' ').trim().slice(0, 70)}"), and the ` +
            `spliced-in part${built.dynamicParts.length === 1 ? ' is' : 's are'} ` +
            `${built.dynamicParts.slice(0, 3).map((p) => `\`${p}\``).join(', ')}. ` +
            `If any of those can be influenced by a user, they can rewrite the query.`,
        };
      }
      return null;
    }

    /* ---- Case 2: SQL is built into a variable first ----
     * `const sql = "SELECT ... " + id;` then later `db.query(sql)`.
     * The SIGNATURE pass cannot connect those two statements - that is data-flow
     * analysis, and the taint engine does it now. This branch stays as the
     * fallback for everything the tracer could not confirm: no recognised
     * source, a value arriving from another file, a framework we do not model.
     * When the tracer DOES confirm it, the verified finding supersedes this one
     * automatically, so the two never both appear.                          */
    const assignment = asAssignment(shape);
    if (assignment) {
      // The scope gate. Without it, assigning a large object literal to a
      // variable let every string inside it merge into one fake "query".
      // This is the check that stopped Defuse reporting its own rule files.
      if (!isStringBuildingExpression(assignment.value, language)) return null;
      const built = analyzeStringExpression(assignment.value, language);
      if (!built.isDynamic) return null;
      if (!looksLikeSql(built.literalText)) return null;
      const buildProof = constantProof(assignment.value, built.dynamicParts, language);
      if (buildProof) {
        if (buildProof.reasoned) ctx.noteClean?.('sql-injection', assignment.node, buildProof.reason);
        return null;
      }
      if (partsAreGuarded(assignment.value, built.dynamicParts, language)) return null;
      if (built.dynamicParts.every((part) => expandsOnlyPlaceholders(part))) return null;

      return {
        node: assignment.node,
        severity: 'high',
        message: `SQL string \`${assignment.targetName}\` is built with ${built.mechanism}`,
        reasoning:
          `\`${assignment.targetName}\` is assigned a string that reads like SQL and was ` +
          `assembled using ${MECHANISM_WORDS[built.mechanism] ?? built.mechanism}. ` +
          `The tracer did not confirm that this variable reaches a database call, so ` +
          `this is reported as dangerous construction, not as a confirmed injection.`,
        limitations:
          'UNVERIFIED (signature-based): we saw SQL text being assembled. We did NOT verify ' +
          'that it reaches a query method, and we did NOT verify that any part is ' +
          'attacker-controlled. The data-flow engine ran and could not confirm either step ' +
          'here - most often because no recognised source feeds it, or the value comes from ' +
          'another file.',
      };
    }

    return null;
  },
};

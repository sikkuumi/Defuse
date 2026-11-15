/**
 * PATH TRAVERSAL  (CWE-22, OWASP A01:2025 - Broken Access Control)
 *
 * WHAT THE BUG IS, in plain language:
 * The server opens a file whose name the request chose.
 *
 *     res.sendFile(path.join(__dirname, 'uploads', req.query.name));
 *
 * The code means "a file in uploads". The request sends
 * `../../../etc/passwd`, and `..` walks up one folder per step until it is
 * out of uploads and anywhere the server process can read - its own source,
 * its `.env`, the keys on the box. On a write or a delete it is worse.
 *
 * THE FIX: keep only the file name (`path.basename`, `os.path.basename`,
 * `secure_filename`, `filepath.Base`, `Path.getFileName`), or resolve the
 * full path and check that it still starts with the folder you meant. Or
 * hand the folder to an API that refuses to leave it (Express `sendFile`
 * with `root`, Flask `send_from_directory`).
 *
 * ============================================================================
 * WHY THIS RULE HAS NO SIGNATURE PASS
 * ============================================================================
 * Same reason as SSRF: "this code opens a file" is what programs do. Only a
 * traced path from a request value to the open is a finding, so `check()`
 * returns null and the taint engine emits every one.
 *
 * A path from the COMMAND LINE, the environment or the terminal is chosen by
 * whoever runs the program, who could open that file themselves. It is
 * reported low, as to review, not proven: it matters only when the program
 * runs with more rights than its caller (setuid, a service, a CGI script).
 */

import { type Rule, type RuleHit } from './contract.js';

export const pathTraversalRule: Rule = {
  id: 'path-traversal',
  name: 'File path the user chose',
  cwe: 'CWE-22',
  owasp: 'A01:2025 Broken Access Control',
  severity: 'high',
  summary: 'The server opens a file path the request may choose, so `../` could reach files outside the folder the code meant.',
  fix:
    'Keep only the file name (basename / secure_filename / filepath.Base), or resolve the path and check it still starts with the intended folder.',
  explanation:
    'The code means "a file in this folder", but the name comes from the request, ' +
    'and every `../` in it climbs one folder up. Enough of them and the server reads, ' +
    'writes or deletes any file its process can reach: its own source, its secrets, ' +
    'the keys on the machine. Keep only the last name in the path, or resolve the ' +
    'full path and check it still starts with the folder you meant before opening it.',
  limitations:
    'FLOW-VERIFIED ONLY: "opens a file" describes almost every program, so there is no ' +
    'pattern pass and every finding comes from a traced path. A path from the command ' +
    'line, the environment or the terminal is chosen by whoever runs the program and is ' +
    'reported low, to review. A path opened after a prefix check (`resolved.startsWith(base)`) ' +
    'or a `..` blocklist in the same function is reported to review, never proven and never ' +
    'cleared: what the check compares is NOT read, so a correct one and a wrong one look the ' +
    'same here. path.join, path.resolve and filepath.Clean are NOT treated as fixes, because ' +
    'none of them stops `../`. A "not found" answer before the open (`if (!x) return res.status(404)`, ' +
    'abort(404), Http404) is read as a possible lookup of known names and also gives to review: ' +
    'what the lookup accepts is NOT read, and any 404 above the open in the function counts, ' +
    'even one about a different value.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Data-flow only. Covers fs / fs.promises / fs-extra reads, writes, deletes and directory listings, destructured readFileSync-style names, and Express res.sendFile / res.download without a root option. NOT covered: a bare readFile() whose import we cannot see.',
    },
    typescript: {
      status: 'implemented',
      note: 'Data-flow only. Identical to JavaScript.',
    },
    python: {
      status: 'implemented',
      note: 'Data-flow only. Covers open(), os file and directory calls, shutil copy / move / rmtree, and Flask send_file. NOT covered: pathlib (Path(x).read_text()), where the path lives in an object the tracer does not follow.',
    },
    java: {
      status: 'implemented',
      note: 'Data-flow only. Covers new File / FileInputStream / FileOutputStream / FileReader / FileWriter / RandomAccessFile / FileSystemResource and the java.nio Files calls that open a path (readAllBytes, newInputStream, write, delete, ...). Paths.get / Path.of only build a path and are followed, not reported. NOT covered: a Path held in a field and opened in another method.',
    },
    php: {
      status: 'implemented',
      note: 'Data-flow only. Covers file_get_contents, fopen, readfile, file, file_put_contents, unlink, opendir, scandir, copy, rename, mkdir and rmdir. NOT covered: include / require, which are statements, not calls, and are not in the sink tables.',
    },
    go: {
      status: 'implemented',
      note: 'Data-flow only. Covers os and ioutil Open / OpenFile / ReadFile / WriteFile / Create / Remove / RemoveAll / ReadDir / Mkdir / Rename and http.ServeFile. NOT covered: http.FileServer, which is configured once rather than called with a path.',
    },
    c: {
      status: 'implemented',
      note: 'Data-flow only. Covers fopen, freopen, open, openat, creat, remove, unlink, rename and opendir. argv, getenv and stdin are reported low, to review: they are chosen by whoever runs the program.',
    },
    cpp: {
      status: 'partial',
      note: 'PARTIAL: the C library calls only. std::ifstream / std::ofstream and std::filesystem are NOT modelled - a stream is opened by a declaration, not a call.',
    },
  },
  /* Deliberately silent: see the header. The taint engine emits every finding for this rule id. */
  check(): RuleHit | null {
    return null;
  },
};

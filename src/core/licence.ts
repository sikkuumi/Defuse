/**
 * THE LICENCE, IN ONE PLACE
 * =========================
 *
 * WHY A MODULE AND NOT A STRING IN THREE FILES.
 *
 * This project has been bitten four times by the same shape of bug: a fact
 * written down in prose next to the same fact held in data, and the two
 * drifting apart. The README claimed 112 checks while 207 ran. It claimed
 * 13.8% recall for roughly twenty versions after that stopped being true. The
 * engine's own limitation text explained the memory ceiling with a cause that
 * a two-line experiment disproved.
 *
 * A licence is a worse place for that to happen than a count is. "This is
 * AGPL-3.0" printed in a terminal, "UNLICENSED" in package.json and an MIT file
 * on disk is not a cosmetic inconsistency - it is three different legal claims
 * about the same program, and the person who gets hurt is whoever believed one
 * of them. So the licence is declared once here, and a test fails if the
 * LICENSE file or package.json disagrees.
 *
 * WHY AGPL-3.0 SPECIFICALLY.
 *
 * The tool can be run as a network service - `npm run ui` serves the browser
 * shell, and the same compiled engine runs inside it. Under a permissive
 * licence somebody could host exactly that, modify it, and never publish a
 * line. Section 13 of the AGPL is the clause that closes it: anyone who runs a
 * MODIFIED version and lets other people interact with it over a network must
 * offer those users the corresponding source.
 *
 * Note what that does NOT say. Using this tool on your own private code puts no
 * obligation on you whatsoever, and neither does running it unmodified inside
 * your company. The obligation attaches to distributing or network-serving a
 * CHANGED version. Scanning a closed-source repository with it is exactly the
 * intended use and carries no licence consequence for the code being scanned.
 */

/** SPDX identifier. Must match package.json's `license` field exactly. */
export const LICENCE_SPDX = 'AGPL-3.0-only';

/** The first line of the LICENSE file, checked against it by the test suite. */
export const LICENCE_FILE_HEADING = 'GNU AFFERO GENERAL PUBLIC LICENSE';

/** One line, for the bottom of `--help`. */
export const LICENCE_LINE =
  `${LICENCE_SPDX} - free to use, including on closed-source code. ` +
  'If you MODIFY it and let others use it over a network, section 13 says you ' +
  'must offer them the source. See LICENSE.';

/**
 * The section 13 notice, for the browser UI.
 *
 * The UI is the reason the licence is AGPL rather than GPL, so this is the one
 * place the notice is not merely good manners. It is shown rather than buried
 * in a file nobody opens, because section 13 says "prominently offer" and a
 * link in a LICENSE file the user never sees is not an offer.
 */
export const NETWORK_SOURCE_NOTICE =
  `Defuse is ${LICENCE_SPDX}. This page runs the same analysis engine as the ` +
  'command line, entirely in your browser - nothing you load here is uploaded ' +
  'anywhere. If you are running a MODIFIED copy of this tool as a service for ' +
  'other people, the licence requires you to offer them its source.';

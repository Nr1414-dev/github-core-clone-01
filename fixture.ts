// Fixture identity: the fixed scenario the suite addresses, VERIFIED from the kit (not assumed).
//
// - program/env/src/wire.ts:752: SCENARIO_SEED = 0x6a09e667f3bcc909n is a fixed constant; the
//   scenario is built once from it (wire.ts:1263 buildScenario) and is identical in practice and
//   scored trials. The per-trial instance seed (rules/instance.yaml) only changes the bearer
//   token and the trial clock (cli/makefun.mjs trialValues); it does not change the scenario.
// - practice/trial-0/reference/scenario.json confirms scenario_seed "6a09e667f3bcc909".
// - The values below were produced by running the kit's own buildScenario() read-only with
//   Node 22.23.5 (21 Nov 2026): viewer adaiversen (id 1000), teammate quinnkeller (1001),
//   stranger olgabauer (1002), org faint-meadow-org.
//
// Why the entry needs these at all: the bearer token is an opaque derived value
// (shpat_<32 hex>, cli/makefun.mjs:242273) and POST /user/repos carries no owner in its body,
// yet the suite addresses repos by scenario.viewer.login (checks-rest.ts:137) and expects a 404
// under the stranger's login for the same repo name (checks-rest.ts:741-743). The token's owner
// is therefore this fixed login; there is no other channel that can name it.

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const TEAMMATE_LOGIN = 'quinnkeller';
export const TEAMMATE_ID = 1001;
export const STRANGER_LOGIN = 'olgabauer';
export const STRANGER_ID = 1002;
export const ORG_LOGIN = 'faint-meadow-org';

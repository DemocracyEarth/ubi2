import { buildQuickLaunchImagePublisherRoleDocuments } from "../app/quick-launch-image-release";

const accountId = process.env.QUICK_LAUNCH_AWS_ACCOUNT_ID?.trim() ?? "";
const documents = buildQuickLaunchImagePublisherRoleDocuments(accountId);

// Repository/account identifiers are non-secret. This command never calls AWS and never accepts a
// credential, secret reference or image-push token.
console.log(JSON.stringify({ transactionFree: true, mutatesAws: false, ...documents }, null, 2));

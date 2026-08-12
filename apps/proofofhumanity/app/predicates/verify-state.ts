export type ChainCredentialState =
  | "idle"
  | "checking"
  | "ready"
  | "missing"
  | "wrong-owner"
  | "expired"
  | "unavailable";

export interface VerificationStateInput {
  accountConnected: boolean;
  chainName: string;
  chainState: ChainCredentialState;
  claimAvailable: boolean;
  consumerValid: boolean;
  contextValid: boolean;
  countrySelected: boolean;
  hasCredential: boolean;
  nationalitySelected: boolean;
}

export interface VerificationGuidance {
  canIssue: boolean;
  eyebrow: string;
  title: string;
  body: string;
}

export function verificationGuidance(input: VerificationStateInput): VerificationGuidance {
  if (!input.hasCredential) {
    return {
      canIssue: false,
      eyebrow: "Step 1 of 3",
      title: "Prepare your private claims first",
      body: "Complete Self verification and mint a Proof-of-Humanity credential in this tab. Nothing is loading yet.",
    };
  }
  if (!input.claimAvailable) {
    return {
      canIssue: false,
      eyebrow: "Claim not prepared",
      title: "Add this fact with Self",
      body: "This browser credential does not contain the selected fact. Re-verify and opt into it before creating a proof.",
    };
  }
  if (!input.accountConnected) {
    return {
      canIssue: false,
      eyebrow: "Step 2 of 3",
      title: "Connect the credential owner",
      body: "Connect the same wallet that received the soulbound token. Connecting does not spend gas or request a signature.",
    };
  }
  if (input.chainState === "checking" || input.chainState === "idle") {
    return {
      canIssue: false,
      eyebrow: "Checking contract",
      title: `Confirming your credential on ${input.chainName}`,
      body: "The app is reading the deployed ProofOfHumanity contract. This is free and does not use your wallet.",
    };
  }
  if (input.chainState === "missing") {
    return {
      canIssue: false,
      eyebrow: "Mint required",
      title: `No credential found on ${input.chainName}`,
      body: "Mint the soulbound credential on this network, then return in the same browser tab.",
    };
  }
  if (input.chainState === "wrong-owner") {
    return {
      canIssue: false,
      eyebrow: "Wallet mismatch",
      title: "Switch to the wallet that owns this credential",
      body: "The selected credential exists, but the connected address is not its on-chain owner.",
    };
  }
  if (input.chainState === "expired") {
    return {
      canIssue: false,
      eyebrow: "Credential expired",
      title: "Refresh your Proof of Humanity",
      body: "Re-verify with Self and refresh the soulbound credential before requesting a new fact proof.",
    };
  }
  if (input.chainState === "unavailable") {
    return {
      canIssue: false,
      eyebrow: "Network unavailable",
      title: `We could not read ${input.chainName}`,
      body: "The public RPC may be temporarily unavailable. Retry shortly or select another network where you minted.",
    };
  }
  if (input.nationalitySelected && !input.countrySelected) {
    return {
      canIssue: false,
      eyebrow: "One detail missing",
      title: "Choose a country",
      body: "Search by country name or code, then select one result. The artifact reveals only whether it matches.",
    };
  }
  if (!input.contextValid) {
    return {
      canIssue: false,
      eyebrow: "One detail missing",
      title: "Name this verification context",
      body: "Use a short purpose such as membership:season-1. It prevents the proof from being reused for another action.",
    };
  }
  if (!input.consumerValid) {
    return {
      canIssue: false,
      eyebrow: "One detail missing",
      title: "Enter the receiving app or contract",
      body: "For a personal test, use your connected wallet. For an integration, use the consumer contract address.",
    };
  }
  return {
    canIssue: true,
    eyebrow: "Ready · no gas required",
    title: "Create your private fact proof",
    body: "The issuer will evaluate one fact, sign its Boolean result, and check it against the deployed verifier contract.",
  };
}

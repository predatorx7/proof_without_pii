import {
    Proof,
    TeeAttestation,
    verifyProof,
    VerifyAttestationConfig,
    fetchProviderConfigs
} from '@reclaimprotocol/js-sdk';
import assert from 'assert';

export interface ParsedProofContext {
    extractedParameters: Record<string, string>;
    attestationNonce: string;
    reclaimSessionId: string;
    attestationNonceData: {
        applicationId: string;
        sessionId: string;
        timestamp: string;
    }
    providerHash: string;
    pcr0_k?: string;
    pcr0_t?: string;
    tee_session_id?: string;
}

export interface ClaimParameters {

}

export interface ParsedProofParameters {
    proxySessionId: string;
}

export interface ProofWithoutPII {
    claimData: {
        context: ParsedProofContext
        parameters: ParsedProofParameters;
        timestampS: number;
    }
    teeAttestation?: TeeAttestation
}

export interface SessionLogsResponse {
    readonly message?: string;
    readonly data?: SessionLog[];
}

export interface SessionLog {
    readonly sessionId?: string;
    readonly date?: Date;
    readonly deviceId?: string;
    readonly deviceType?: string;
    readonly providerId?: string;
    readonly applicationId?: string;
    readonly appCreatorId?: string;
    readonly publicIpAddress?: string;
    readonly logType?: string;
    readonly appName?: string;
    readonly providerName?: string;
    readonly metadata?: string;
    readonly platform?: string;
}

export interface ProofGenerationSuccessInformation {
    readonly provider_id?: string;
    readonly provider_version?: string;
    readonly provider_hashes?: string[];
    readonly claim_timestamp?: string;
    readonly attestation_nonce?: string;
    readonly pcr0_k?: string;
    readonly pcr0_t?: string;
    readonly tee_session_ids?: string[];
}

export async function fetchSessionInfoBy(
    sessionId: string
): Promise<SessionLogsResponse> {
    try {
        const response = await fetch(
            `https://logs.reclaimprotocol.org/api/analytics-logs/session/${sessionId}`
        );

        const json = await response.json();
        return json as SessionLogsResponse;
    } catch (e) {
        console.error('Error in fetching session info by sessionId:', e);
        throw new Error('Error in fetching session info by sessionId: ' + e);
    }
}

export interface SessionVerificationInfo {
    extractedParameters?: Record<string, any>;
    provider_id?: string;
    provider_version?: string;
    provider_hashes?: string[];
    claim_timestamp?: string;
    attestation_nonce?: string;
    verificationConfig: VerifyAttestationConfig;
}

const contactSupport = 'Please contact Reclaim Protocol Support team or mail us at support@reclaimprotocol.org.';

const providerInfo = async (effectiveProviderId: string, effectiveProviderVersion: string, errorMessage?: string) => {
    const providerConfig = await fetchProviderConfigs(effectiveProviderId, effectiveProviderVersion, []);
    const providerInfo = await (providerConfig as any).info;
    if (errorMessage) {
        return { providerInfo, canProviderBeFaulty: errorMessage.includes(contactSupport) };
    } else {
        const providers = providerConfig.providers;
        if (!providers || providers.length == 0) {
            return { providerInfo, canProviderBeFaulty: 'No providers' };
        }
        const provider = providers[0] as (typeof providers[0] & { isScriptRequestingClaim: boolean });
        const hasMissingInjectedRequestData = provider.isScriptRequestingClaim && ((provider.allowedInjectedRequestData ?? []).length == 0);
        const hasMissingBodySniff = provider.requestData.map(it => it?.method?.toUpperCase() == 'POST' && it?.bodySniff?.enabled != true).filter(it => it == true).length > 0;
        return { providerInfo, canProviderBeFaulty: hasMissingInjectedRequestData || hasMissingBodySniff };
    }
}

export async function verifySession(sessionId: string, info: SessionVerificationInfo) {
    const session = await fetchSessionInfoBy(sessionId);
    if (!session.data?.length) {
        throw new Error('No information about this session is available');
    }
    const proofGenerationSuccess = session.data.filter(it => it.logType?.toUpperCase().trim() == 'PROOF_GENERATION_SUCCESS')[0];
    if (!proofGenerationSuccess) {
        throw new Error('No proof information available');
    }

    assert(proofGenerationSuccess.metadata, 'No metadata in proofGenerationSuccess');

    const metadata = JSON.parse(proofGenerationSuccess.metadata || '{}') as ProofGenerationSuccessInformation;
    const claimTimestamp = info.claim_timestamp ?? metadata.claim_timestamp ?? '1';
    const attestationNonce = info.attestation_nonce ?? metadata.attestation_nonce ?? '1';

    if (!metadata.provider_id || !metadata.provider_version || !metadata.provider_hashes || metadata.provider_hashes.length == 0) {
        throw new Error('Unsupported');
    }

    const proofWithoutPii = metadata.provider_hashes.map((hash, index): ProofWithoutPII => {
        return {
            claimData: {
                context: {
                    extractedParameters: info.extractedParameters ?? {},
                    attestationNonce: attestationNonce,
                    reclaimSessionId: sessionId,
                    attestationNonceData: {
                        applicationId: proofGenerationSuccess.applicationId!,
                        sessionId: sessionId,
                        timestamp: claimTimestamp,
                    },
                    providerHash: hash,
                    pcr0_k: metadata.pcr0_k,
                    pcr0_t: metadata.pcr0_t,
                    tee_session_id: metadata.tee_session_ids ? metadata.tee_session_ids[index] : undefined,
                },
                parameters: {
                    proxySessionId: sessionId
                },
                timestampS: +claimTimestamp,
            }
        }
    });

    const proofs: Proof[] = proofWithoutPii.map((proof): Proof => {
        return {
            ...proof,
            claimData: {
                ...proof.claimData,
                context: JSON.stringify({
                    ...proof.claimData.context,
                }),
            } as unknown as Proof['claimData'],
            extractedParameterValues: undefined,
            signatures: [],
            witnesses: []
        } as unknown as Proof
    });

    const effectiveProviderId = info.provider_id ?? metadata.provider_id
    const effectiveProviderVersion = info.provider_version ?? metadata.provider_version

    try {
        const result = await verifyProof(
            proofs,
            {
                hasNoPii: true,
                providerId: effectiveProviderId,
                providerVersion: info.provider_version ?? metadata.provider_version,
                ...info.verificationConfig
            }
        );

        const providerConfig = await providerInfo(effectiveProviderId, effectiveProviderVersion, result.isVerified ? undefined : `Error: ${result.error}`);

        return { result, ...providerConfig };
    } catch (error) {
        const providerConfig = await providerInfo(effectiveProviderId, effectiveProviderVersion, `Error: ${error}`);

        return { result: { isVerified: false }, error, ...providerConfig };
    }
}

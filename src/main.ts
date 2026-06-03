import { verifySession } from "./validate"

const main = async () => {
    try {
        const response = await verifySession("99f86066d7", {
            verificationConfig: {
                teeAttestation: undefined,
                attestorTeeAttestation: undefined
            }
        });
        console.info({ response: JSON.stringify(response, null, 2) });
    } catch (error) {
        console.error({ error });
    }
}

main();

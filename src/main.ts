import { verifySession } from "./validate"
import readline from "readline/promises";

const main = async () => {
    let rl: readline.Interface | undefined;
    try {
        rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        const sessionId = await rl.question('Enter session Id: ');

        if (!sessionId) {
            throw new Error('No session ID provided');
        }

        const response = await verifySession(sessionId, {
            verificationConfig: {
                teeAttestation: undefined,
                attestorTeeAttestation: undefined
            }
        });
        console.info(JSON.stringify(response, null, 2));

    } catch (error) {
        console.error({ error });
    } finally {
        rl?.close();
    }
}

main();
